#include "asm_types_workaround.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
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
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, MAX_SUBS);
    __type(key, __u32);  // Dummy key or group-specific index
    __type(value, __u32);  // veth ifindex
} fwd_map SEC(".maps");

// Downstream XDP: attach to veths, capture IGMP join/leave, notify userspace, drop packet
SEC("xdp")
int xdp_downstream(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_IGMP) return XDP_PASS;

    struct igmphdr *igmp = (void *)(ip + 1);
    if ((void *)(igmp + 1) > data_end) return XDP_PASS;

    __be32 group = igmp->group;
    if (group == 0) return XDP_DROP; // Invalid

    __u32 ifidx = ctx->ingress_ifindex;
    __u32 type = 0;

    if (igmp->type == IGMP_HOST_MEMBERSHIP_REPORT || igmp->type == IGMPV2_HOST_MEMBERSHIP_REPORT) {
        type = 1; // join
    } else if (igmp->type == IGMP_HOST_LEAVE_MESSAGE) {
        type = 2; // leave
    }
    if (type == 0) return XDP_DROP;

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
SEC("xdp")
int xdp_upstream(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __be32 daddr = ip->daddr;
    if ((daddr & bpf_htonl(0xF0000000)) != bpf_htonl(0xE0000000)) return XDP_PASS; // not multicast

    if (ip->protocol == IPPROTO_IGMP) return XDP_PASS; // let userspace handle control

    // Use dummy key 0; in production, use group-specific key if multiple maps
    __u32 key = 0;
    __u32 *ifidx = bpf_map_lookup_elem(&fwd_map, &key);
    if (!ifidx) return XDP_PASS;

    // Broadcast to all veths in the devmap (clones packet to multiple interfaces)
    return bpf_redirect_map(&fwd_map, 0, BPF_F_BROADCAST);
}

char _license[] SEC("license") = "GPL";
