// SPDX-License-Identifier: GPL-2.0
#include "asm_types_workaround.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/igmp.h>
#include <linux/in.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 2
#endif
#ifndef IGMPV3_HOST_MEMBERSHIP_REPORT
#define IGMPV3_HOST_MEMBERSHIP_REPORT 0x22
#endif

#define MAX_GROUPS  256
#define MAX_SUBS    128

struct event {
    __u32  type;
    __be32 group;
    __u32  ifindex;
};

/* ── Maps ──────────────────────────────────────────────────────────────────
 *
 * Tier-2 optimisation: a single hash lookup (group_addr → group_id) amortises
 * across N subsequent array lookups (group_id → sub_count, single_if,
 * afxdp_mode, inner devmap).  Array maps deliver ~30–60 ns per access vs
 * ~100–300 ns for hash maps, saving ~420 ns per packet for 4 secondary lookups.
 */

/* group_addr (BE32) → group_id (u32 array index) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_GROUPS);
    __type(key, __be32);
    __type(value, __u32);
} group_id_map SEC(".maps");

/*
 * Inner DEVMAP_HASH prototype.
 * Serves dual purpose:
 *   1. Template that tells the kernel the inner map type for group_map.
 *   2. Pre-populated instance at group_map[0] (used by group_id 0).
 * Each entry stores a host-side ifindex plus an optional egress BPF prog fd,
 * eliminating a separate xdp_downstream invocation at redirect time.
 */
struct inner_devmap {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, MAX_SUBS);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
} inner_devmap_proto SEC(".maps");

/*
 * ARRAY_OF_MAPS: group_id → inner DEVMAP_HASH.
 * Array lookup is a direct index multiply — no hash computation, no collision
 * chain, cache-line-friendly for small MAX_GROUPS.
 * Slot 0 is pre-populated with inner_devmap_proto; slots 1..N are created
 * on demand by userspace when new groups are joined.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_GROUPS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __array(values, struct inner_devmap);
} group_map SEC(".maps") = {
    .values = { [0] = &inner_devmap_proto },
};

/* group_id → subscriber count; drives fast-path selection in xdp_upstream */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_GROUPS);
    __type(key, __u32);
    __type(value, __u32);
} group_sub_count SEC(".maps");

/*
 * group_id → single host-side ifindex.
 * Valid only when group_sub_count[group_id] == 1.
 * Used by the bpf_redirect_peer() fast path which skips devmap indirection
 * and injects directly into the container peer's ingress, saving ~1–2 µs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_GROUPS);
    __type(key, __u32);
    __type(value, __u32);
} group_single_if SEC(".maps");

/*
 * Tier-3: AF_XDP socket map.
 * One slot per container subscriber.  When afxdp_mode[group_id] == 1,
 * xdp_upstream redirects to this map instead of the devmap, delivering the
 * packet zero-copy into the daemon's shared UMEM for descriptor-only fanout.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_SUBS);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

/*
 * group_id → AF-XDP mode flag.
 *   0 = devmap path  (Tier 2, N ≤ AFXDP_SUB_THRESHOLD)
 *   1 = xskmap path  (Tier 3, N > AFXDP_SUB_THRESHOLD)
 * Written by daemon when threshold is crossed; read at line-rate in XDP.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_GROUPS);
    __type(key, __u32);
    __type(value, __u32);
} afxdp_mode SEC(".maps");

/* Ring buffer: IGMP join/leave events to userspace control plane */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");


/* ── igmp_capture — shared IGMP processing ─────────────────────────────────
 *
 * Called by both xdp_downstream (L2/veth) and xdp_downstream_l3 (L3/netkit).
 * Receives a pointer to the start of the IP header plus data_end; parses the
 * IGMP payload, emits a join/leave event to the ring buffer, and drops the
 * frame so the raw IGMP never reaches the upstream router directly.
 *
 * IP options are handled correctly via ip->ihl*4 so the IP Router Alert
 * option (RFC 2113) carried in all IGMP packets does not cause mis-parse.
 * IGMPv1 (0x12), IGMPv2 (0x16), and IGMPv3 (0x22) joins are recognised.
 */
static __always_inline int igmp_capture(struct xdp_md *ctx,
                                        struct iphdr *ip, void *data_end)
{
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_IGMP)
        return XDP_PASS;

    __u32 ihl = ip->ihl;
    if (ihl < 5)
        return XDP_DROP;

    void *igmp_ptr = (void *)ip + (ihl << 2);
    if (igmp_ptr + sizeof(struct igmphdr) > data_end)
        return XDP_DROP;

    struct igmphdr *igmp = igmp_ptr;
    __u32 type = 0;

    switch (igmp->type) {
    case IGMP_HOST_MEMBERSHIP_REPORT:       /* IGMPv1  0x12 */
    case IGMPV2_HOST_MEMBERSHIP_REPORT:     /* IGMPv2  0x16 */
    case IGMPV3_HOST_MEMBERSHIP_REPORT:     /* IGMPv3  0x22 */
        type = 1;
        break;
    case IGMP_HOST_LEAVE_MESSAGE:           /* leave   0x17 */
        type = 2;
        break;
    default:
        return XDP_DROP;
    }

    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->type    = type;
        ev->group   = igmp->group;
        ev->ifindex = ctx->ingress_ifindex;
        bpf_ringbuf_submit(ev, 0);
    }
    return XDP_DROP;
}

/* ── xdp_downstream (L2 mode — veth or netkit-L2) ──────────────────────────
 *
 * Attached to container interfaces that carry a full Ethernet header.
 * Strips the L2 header and delegates to igmp_capture().
 * Selected by the daemon when IFLA_INFO_KIND=="veth" or
 * IFLA_INFO_KIND=="netkit" with IFLA_NETKIT_MODE==NETKIT_L2.
 */
SEC("xdp")
int xdp_downstream(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    return igmp_capture(ctx, ip, data_end);
}

/* ── xdp_downstream_l3 (L3 mode — netkit-L3) ───────────────────────────────
 *
 * Attached to container interfaces in netkit L3 mode (kernel ≥ 6.7).
 * In L3 mode the netkit device strips the Ethernet header before delivering
 * the frame to the peer XDP hook, so the packet starts directly at the IP
 * header.  Parsing an ethhdr that isn't there would mis-identify the IP
 * version field as an EtherType and silently pass all IGMP frames.
 *
 * Selected by the daemon when IFLA_INFO_KIND=="netkit" and
 * IFLA_NETKIT_MODE==NETKIT_L3.
 */
SEC("xdp")
int xdp_downstream_l3(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Packet begins at IP header — no Ethernet header present */
    struct iphdr *ip = data;
    return igmp_capture(ctx, ip, data_end);
}


/* ── xdp_devmap_egress ─────────────────────────────────────────────────────
 *
 * Attached as the per-entry BPF program in each DEVMAP_HASH slot
 * (via bpf_devmap_val.bpf_prog.fd).
 *
 * Runs at redirect time for each container receiving a multicast clone,
 * collapsing what would otherwise be a separate xdp_downstream invocation
 * into the existing redirect path.  ctx->egress_ifindex identifies the
 * receiving container interface for per-container fixup or stats.
 *
 * Current implementation is a pass-through; extend here for:
 *   - MAC rewriting in veth L2 mode
 *   - Per-interface receive counters (BPF_MAP_TYPE_PERCPU_ARRAY)
 *   - TTL decrement or DSCP remarking
 */
SEC("xdp/devmap")
int xdp_devmap_egress(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}


/* ── xdp_upstream ──────────────────────────────────────────────────────────
 *
 * Attached to the uplink (eth0).  Entirely in the kernel fast path;
 * the userspace daemon is NOT on the multicast data path.
 *
 * Decision tree per packet:
 *
 *  1. Not IPv4 or not multicast (224.0.0.0/4)?  → XDP_PASS  (kernel stack)
 *  2. IGMP (protocol=2)?                        → XDP_PASS  (proxy handles)
 *  3. No group_id registered?                   → XDP_PASS
 *  4. sub_count == 0?                           → XDP_PASS
 *  5. afxdp_mode == 1?                          → xskmap    (Tier 3)
 *  6. sub_count == 1?                           → bpf_redirect_peer()  (Tier 2 fast path)
 *     bpf_redirect_peer skips devmap indirection and TX queue, injecting
 *     directly into the container peer's ingress (~1–2 µs saved vs devmap).
 *  7. sub_count > 1                             → bpf_redirect_map BROADCAST (Tier 2)
 *     Kernel clones xdp_frame per entry; first entry reuses original frame,
 *     subsequent entries pay one memcpy(packet_data) each (~150–400 ns/clone).
 *     xdp_devmap_egress runs per clone at redirect time.
 */
SEC("xdp")
int xdp_upstream(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __be32 daddr = ip->daddr;

    /* 224.0.0.0/4 — multicast range */
    if ((daddr & bpf_htonl(0xF0000000)) != bpf_htonl(0xE0000000))
        return XDP_PASS;

    /* IGMP control traffic: let the kernel and proxy handle it */
    if (ip->protocol == IPPROTO_IGMP)
        return XDP_PASS;

    /* Step 1: hash lookup — group IP → group_id (array index) */
    __u32 *gid_ptr = bpf_map_lookup_elem(&group_id_map, &daddr);
    if (!gid_ptr)
        return XDP_PASS;
    __u32 gid = *gid_ptr;

    /* Step 2: array lookup — group_id → subscriber count (~45 ns) */
    __u32 *cnt_ptr = bpf_map_lookup_elem(&group_sub_count, &gid);
    if (!cnt_ptr || *cnt_ptr == 0)
        return XDP_PASS;
    __u32 count = *cnt_ptr;

    /* Step 3: array lookup — group_id → AF-XDP mode flag (~45 ns) */
    __u32 *axdp = bpf_map_lookup_elem(&afxdp_mode, &gid);
    if (axdp && *axdp)
        /* Tier 3: zero-copy to daemon UMEM; slot 0 is the aggregator XSK */
        return bpf_redirect_map(&xsk_map, 0, XDP_PASS);

    /* Step 4: single-subscriber fast path — bpf_redirect (~45 ns lookup) */
    if (count == 1) {
        __u32 *ifidx = bpf_map_lookup_elem(&group_single_if, &gid);
        if (ifidx && *ifidx)
            /*
             * Redirect via TX queue of the host-side netkit/veth peer;
             * the kernel delivers the frame to the container RX path.
             * bpf_redirect_peer is TC-only and not available in XDP.
             */
            return bpf_redirect(*ifidx, 0);
    }

    /* Step 5: multi-subscriber broadcast via ARRAY_OF_MAPS devmap (~45 ns) */
    void *inner = bpf_map_lookup_elem(&group_map, &gid);
    if (!inner)
        return XDP_PASS;

    /*
     * BPF_F_BROADCAST: kernel clones xdp_frame to every devmap entry.
     * BPF_F_EXCLUDE_INGRESS: prevents looping packet back out eth0.
     */
    return bpf_redirect_map(inner, 0,
                            BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

char _license[] SEC("license") = "GPL";
