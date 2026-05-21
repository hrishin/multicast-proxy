#ifndef MULTICAST_H
#define MULTICAST_H

#include <stdint.h>

#define EVENT_JOIN   1
#define EVENT_LEAVE  2

#define MAX_GROUPS   256
#define MAX_SUBS     128

/*
 * Subscriber count threshold above which a group switches from the devmap
 * broadcast path (Tier 2) to the AF-XDP shared-UMEM path (Tier 3).
 * At this crossover the cost of N-1 xdp_frame_copy()s exceeds the
 * AF-XDP descriptor-fanout overhead assuming ~2 µs busy-poll latency.
 */
#define AFXDP_SUB_THRESHOLD  4

struct event {
    uint32_t  type;     /* EVENT_JOIN or EVENT_LEAVE */
    uint32_t  group;    /* multicast group, network byte order */
    uint32_t  ifindex;  /* host-side interface index */
};

/* Per-group runtime state (userspace only) */
struct group_state {
    uint32_t  group_addr;              /* multicast IP, network byte order */
    uint32_t  group_id;                /* slot in array maps               */
    uint32_t  sub_count;
    int       devmap_fd;               /* inner DEVMAP_HASH fd             */
    int       igmp_sock;               /* kernel IGMP socket (join/leave)  */
    uint32_t  slot_ifindex[MAX_SUBS];  /* slot  → host-side ifindex        */
    uint8_t   slot_used[MAX_SUBS];
    uint32_t  next_slot;
};

/* Interface link mode — drives BPF program selection at attach time */
#define IFACE_L2_MODE  0   /* veth or netkit-L2: Ethernet header present      */
#define IFACE_L3_MODE  1   /* netkit-L3: packet starts at IP, no Ethernet hdr */

/* Per-interface runtime state (userspace only) */
struct iface_state {
    uint32_t  ifindex;
    int       link_fd;    /* bpf_link fd (reserved for future bpf_link use) */
    int       xdp_flags;  /* XDP_FLAGS_DRV_MODE or XDP_FLAGS_SKB_MODE used  */
    int       l3_mode;    /* IFACE_L2_MODE or IFACE_L3_MODE                 */
};

#endif /* MULTICAST_H */
