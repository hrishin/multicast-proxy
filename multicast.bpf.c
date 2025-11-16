#include "asm_types_workaround.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/igmp.h>
#include <linux/in.h>

// Define constants that might not be available on older Ubuntu versions
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 2
#endif

#ifndef IGMP_HOST_MEMBERSHIP_REPORT
#define IGMP_HOST_MEMBERSHIP_REPORT 0x16
#endif

#ifndef IGMPV2_HOST_MEMBERSHIP_REPORT
#define IGMPV2_HOST_MEMBERSHIP_REPORT 0x16
#endif

#ifndef IGMP_HOST_LEAVE_MESSAGE
#define IGMP_HOST_LEAVE_MESSAGE 0x17
#endif

#ifndef IGMPV3_HOST_MEMBERSHIP_REPORT
#define IGMPV3_HOST_MEMBERSHIP_REPORT 0x22
#endif

#define MAX_SUBS 128  // Max subscribers per group; adjust as needed

struct event {
    __u32 type; // 1: join, 2: leave
    __be32 group;
    __u32 ifindex; // veth ifindex
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Devmap for broadcast redirection (stores veth ifindexes for each group; key is dummy/group-specific)
// Note: Using DEVMAP instead of DEVMAP_HASH for better compatibility
// Using proper struct format for BTF compatibility (bpf_devmap_val is defined in linux/bpf.h)
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, MAX_SUBS);
    __type(key, __u32);  // Dummy key or group-specific index
    __type(value, struct bpf_devmap_val);  // Kernel-defined struct with ifindex and bpf_prog_id
} fwd_map SEC(".maps");

// Downstream XDP: attach to veths, capture IGMP join/leave, notify userspace, drop packet
SEC("xdp/xdp_downstream")
int xdp_downstream(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    // Check IP header length (IHL is in 32-bit words, minimum 5)
    __u8 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60) return XDP_PASS; // Invalid IP header length
    
    if (ip->protocol != IPPROTO_IGMP) return XDP_PASS;

    // IGMP header starts after variable-length IP header
    struct igmphdr *igmp = (void *)((char *)ip + ip_hdr_len);
    if ((void *)(igmp + 1) > data_end) return XDP_PASS;
    
    // Read IGMP type first
    __u8 igmp_type = igmp->type;
    
    // For IGMPv2 membership reports, the packet is sent TO the multicast group
    // So we use the IP destination address, which is more reliable
    // For leave messages, we use igmp->group
    __be32 group = 0;
    __u32 ifidx = ctx->ingress_ifindex;
    __u32 type = 0;

    // Handle IGMPv2 membership report (0x16)
    if (igmp_type == IGMP_HOST_MEMBERSHIP_REPORT || igmp_type == IGMPV2_HOST_MEMBERSHIP_REPORT) {
        type = 1; // join
        // For membership reports, use IP destination address (the multicast group)
        // This is more reliable than igmp->group which might not always be set correctly
        group = ip->daddr;
    }
    // Handle IGMPv3 membership report (0x22) - for now treat as join
    // Note: IGMPv3 has group records, but the first record's group is at offset 8
    else if (igmp_type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
        type = 1; // join
        // For IGMPv3, group addresses are in group records after the header
        // IGMPv3 reports are sent to 224.0.0.22, not to the group address
        // The actual groups are in group records which we'd need to parse
        // For now, if igmp->group is 0, try to parse first group record
        if (group == 0) {
            // IGMPv3 group record starts at offset 8 from igmp header
            // struct: type (1), aux_data_len (1), num_sources (2), group (4)
            void *grp_rec = (void *)(igmp + 1);
            if ((void *)(grp_rec + 8) <= data_end) {
                // Try to read group from first group record
                __be32 *grp_ptr = (__be32 *)((char *)grp_rec + 4);
                if (grp_ptr + 1 <= (__be32 *)data_end) {
                    group = *grp_ptr;
                }
            }
            // If still 0, fall back to checking if we can infer from context
            // (This is imperfect but better than dropping)
        }
    }
    // Handle leave message (0x17) - works for both v2 and v3
    else if (igmp_type == IGMP_HOST_LEAVE_MESSAGE) {
        type = 2; // leave
        // For leave messages, use igmp->group field
        group = igmp->group;
    }
    
    if (type == 0) return XDP_DROP; // Not a join/leave message we care about
    
    if (group == 0) return XDP_DROP; // Invalid group

    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->type = type;
        ev->group = group;
        ev->ifindex = ifidx;
        bpf_ringbuf_submit(ev, 0);
    }

    return XDP_DROP;
}

// Upstream XDP: attach to eth0, broadcast multicast data to subscribed veths
SEC("xdp/xdp_upstream")
int xdp_upstream(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    // Check IP header length
    __u8 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60) return XDP_PASS; // Invalid IP header length

    __be32 daddr = ip->daddr;
    if ((daddr & bpf_htonl(0xF0000000)) != bpf_htonl(0xE0000000)) return XDP_PASS; // not multicast

    if (ip->protocol == IPPROTO_IGMP) return XDP_PASS; // let userspace handle control


    // Log the destination multicast address to the events ring buffer for monitoring
    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->type = 3; // type 3 = multicast data
        ev->group = daddr;
        ev->ifindex = ctx->ingress_ifindex;
        bpf_ringbuf_submit(ev, 0);
    }
    // Check if map has any entries
    // With BPF_F_BROADCAST, the key parameter is ignored and all entries are used
    // But we need to verify the map has at least one entry
    // Check key 0 first (most common case)
    __u32 key = 0;
    struct bpf_devmap_val *val = bpf_map_lookup_elem(&fwd_map, &key);
    // If key 0 doesn't exist, try a few more keys (unrolled for verifier)
    if (!val) {
        key = 1;
        val = bpf_map_lookup_elem(&fwd_map, &key);
    }
    if (!val) {
        key = 2;
        val = bpf_map_lookup_elem(&fwd_map, &key);
    }
    if (!val) {
        key = 3;
        val = bpf_map_lookup_elem(&fwd_map, &key);
    }
    // If still no entries found, pass the packet
    if (!val) return XDP_PASS;

    // Broadcast to all veths in the devmap (clones packet to multiple interfaces)
    // Note: BPF_F_BROADCAST ignores the key and broadcasts to all entries
    return bpf_redirect_map(&fwd_map, 0, BPF_F_BROADCAST);
}

char _license[] SEC("license") = "GPL";
