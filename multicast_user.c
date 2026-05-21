// SPDX-License-Identifier: GPL-2.0
/*
 * IGMP Proxy Daemon — userspace control plane.
 *
 * Responsibilities (data plane handled entirely by eBPF):
 *   - Load and attach BPF programs via libbpf skeleton.
 *   - Watch for new/departing container interfaces via netlink RTNLGRP_LINK.
 *   - Attach xdp_downstream to each container's host-side netkit/veth peer.
 *   - Consume IGMP join/leave events from the BPF ring buffer.
 *   - Maintain per-group BPF map state:
 *       group_id_map  — group IP → sequential array index
 *       group_map     — array-of-maps: group_id → inner DEVMAP_HASH
 *       group_sub_count — subscriber counts
 *       group_single_if — single-subscriber ifindex for redirect_peer path
 *       afxdp_mode    — flag to switch group to Tier-3 AF-XDP path
 *   - Issue IGMP membership reports / leaves on the uplink via kernel
 *     IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP (kernel manages IGMP state).
 *   - Activate AF-XDP shared-UMEM path (Tier 3) when subscriber count
 *     exceeds AFXDP_SUB_THRESHOLD.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "multicast.h"

/*
 * netkit link-info constants (kernel 6.7+, include/uapi/linux/if_link.h).
 * Defined here with guards so the daemon compiles on older kernel headers
 * that predate netkit while still detecting it correctly at runtime.
 */
#ifndef IFLA_NETKIT_UNSPEC
enum {
    IFLA_NETKIT_UNSPEC,
    IFLA_NETKIT_PEER_INFO,
    IFLA_NETKIT_PRIMARY,
    IFLA_NETKIT_POLICY,
    IFLA_NETKIT_PEER_POLICY,
    IFLA_NETKIT_MODE,           /* u32: 0=NETKIT_L2, 1=NETKIT_L3 */
    __IFLA_NETKIT_MAX,
};
#define NETKIT_L2  0
#define NETKIT_L3  1
#endif
#include "multicast.bpf.skel.h"
#include "afxdp.h"

/* ── Global state ──────────────────────────────────────────────────────── */

static volatile int g_running = 1;

static struct multicast_bpf *g_skel;
static int                   g_egress_prog_fd = -1;

/* Per-group state table, indexed by group_id */
static struct group_state g_groups[MAX_GROUPS];

/* Per-interface state (container peers we've attached xdp_downstream to) */
static struct iface_state g_ifaces[MAX_SUBS];
static int                g_n_ifaces;
static pthread_mutex_t    g_iface_lock = PTHREAD_MUTEX_INITIALIZER;

/* Uplink interface name and ifindex */
static char     g_uplink[IFNAMSIZ] = "eth0";
static int      g_uplink_ifindex;

/* AF-XDP context (Tier 3) */
static struct afxdp_ctx g_afxdp;
static int              g_afxdp_active;

/* ── Signal handler ────────────────────────────────────────────────────── */

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ── Utility ───────────────────────────────────────────────────────────── */

static const char *group_str(uint32_t group_net)
{
    static char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &group_net, buf, sizeof(buf));
    return buf;
}

/* Return a pointer to an unused group_state slot, or NULL if table is full */
static struct group_state *alloc_group_slot(void)
{
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (g_groups[i].sub_count == 0 && g_groups[i].devmap_fd == 0) {
            memset(&g_groups[i], 0, sizeof(g_groups[i]));
            g_groups[i].group_id  = (uint32_t)i;
            g_groups[i].devmap_fd = -1;
            g_groups[i].igmp_sock = -1;
            return &g_groups[i];
        }
    }
    return NULL;
}

static struct group_state *find_group(uint32_t group_addr)
{
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (g_groups[i].group_addr == group_addr &&
            (g_groups[i].sub_count > 0 || g_groups[i].devmap_fd >= 0))
            return &g_groups[i];
    }
    return NULL;
}

/* ── Inner DEVMAP_HASH creation ────────────────────────────────────────── */

/*
 * Create a new BPF_MAP_TYPE_DEVMAP_HASH with bpf_devmap_val values so that
 * each entry carries the optional egress BPF program fd (xdp_devmap_egress).
 */
static int create_inner_devmap(void)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    return bpf_map_create(BPF_MAP_TYPE_DEVMAP_HASH,
                          "inner_devmap",
                          sizeof(uint32_t),
                          sizeof(struct bpf_devmap_val),
                          MAX_SUBS,
                          &opts);
}

/* ── IGMP proxy ────────────────────────────────────────────────────────── */

/*
 * Open a UDP socket bound to the uplink and issue IP_ADD_MEMBERSHIP so the
 * kernel sends an IGMP membership report upstream and maintains the IGMP
 * state machine (handles queries, refreshes, etc.).
 */
static int igmp_join(struct group_state *gs)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("igmp: socket");
        return -errno;
    }

    /* Bind socket to uplink so IGMP reports egress on the right interface */
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                   g_uplink, strlen(g_uplink)) < 0) {
        perror("igmp: SO_BINDTODEVICE");
        close(sock);
        return -errno;
    }

    /* IP_MULTICAST_TTL must be 1 for IGMP (link-scope) */
    int ttl = 1;
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    struct ip_mreq mreq = {
        .imr_multiaddr.s_addr = gs->group_addr,
        .imr_interface.s_addr = INADDR_ANY,
    };
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        perror("igmp: IP_ADD_MEMBERSHIP");
        close(sock);
        return -errno;
    }

    gs->igmp_sock = sock;
    fprintf(stderr, "igmp: joined %s on %s\n",
            group_str(gs->group_addr), g_uplink);
    return 0;
}

static void igmp_leave(struct group_state *gs)
{
    if (gs->igmp_sock < 0)
        return;

    struct ip_mreq mreq = {
        .imr_multiaddr.s_addr = gs->group_addr,
        .imr_interface.s_addr = INADDR_ANY,
    };
    setsockopt(gs->igmp_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
               &mreq, sizeof(mreq));
    close(gs->igmp_sock);
    gs->igmp_sock = -1;
    fprintf(stderr, "igmp: left %s on %s\n",
            group_str(gs->group_addr), g_uplink);
}

/* ── AF-XDP activation ─────────────────────────────────────────────────── */

static void afxdp_activate_group(struct group_state *gs)
{
    if (!g_afxdp_active) {
        fprintf(stderr,
                "afxdp: not initialised, staying on devmap path for group %s\n",
                group_str(gs->group_addr));
        return;
    }

    uint32_t gid = gs->group_id;
    uint32_t one = 1;
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.afxdp_mode),
                        &gid, &one, BPF_ANY);

    fprintf(stderr,
            "afxdp: activated zero-copy path for group %s (id=%u, subs=%u)\n",
            group_str(gs->group_addr), gid, gs->sub_count);
}

static void afxdp_deactivate_group(struct group_state *gs)
{
    uint32_t gid  = gs->group_id;
    uint32_t zero = 0;
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.afxdp_mode),
                        &gid, &zero, BPF_ANY);
}

/* ── Group join logic ──────────────────────────────────────────────────── */

static int group_add_subscriber(struct group_state *gs, uint32_t ifindex)
{
    /* Find a free devmap slot */
    uint32_t slot = MAX_SUBS;
    for (uint32_t s = 0; s < MAX_SUBS; s++) {
        if (!gs->slot_used[s]) { slot = s; break; }
    }
    if (slot == MAX_SUBS) {
        fprintf(stderr, "group %s: devmap full\n",
                group_str(gs->group_addr));
        return -ENOSPC;
    }

    struct bpf_devmap_val val = {
        .ifindex       = ifindex,
        .bpf_prog.fd   = g_egress_prog_fd,  /* attaches xdp_devmap_egress */
    };

    int err = bpf_map_update_elem(gs->devmap_fd, &slot, &val, BPF_ANY);
    if (err) {
        fprintf(stderr, "group %s: devmap update failed: %s\n",
                group_str(gs->group_addr), strerror(errno));
        return -errno;
    }

    gs->slot_ifindex[slot] = ifindex;
    gs->slot_used[slot]    = 1;
    gs->sub_count++;
    gs->next_slot = slot + 1;

    /* Update group_sub_count array map */
    uint32_t gid = gs->group_id;
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_sub_count),
                        &gid, &gs->sub_count, BPF_ANY);

    /* Maintain group_single_if for redirect_peer fast path */
    if (gs->sub_count == 1) {
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_single_if),
                            &gid, &ifindex, BPF_ANY);
    } else {
        uint32_t zero = 0;
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_single_if),
                            &gid, &zero, BPF_ANY);
    }

    /* Switch to AF-XDP path if above threshold */
    if (gs->sub_count > AFXDP_SUB_THRESHOLD)
        afxdp_activate_group(gs);

    return 0;
}

static void group_remove_subscriber(struct group_state *gs, uint32_t ifindex)
{
    uint32_t slot = MAX_SUBS;
    for (uint32_t s = 0; s < MAX_SUBS; s++) {
        if (gs->slot_used[s] && gs->slot_ifindex[s] == ifindex) {
            slot = s;
            break;
        }
    }
    if (slot == MAX_SUBS)
        return;  /* not found */

    bpf_map_delete_elem(gs->devmap_fd, &slot);
    gs->slot_used[slot]    = 0;
    gs->slot_ifindex[slot] = 0;

    if (gs->sub_count > 0)
        gs->sub_count--;

    uint32_t gid = gs->group_id;
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_sub_count),
                        &gid, &gs->sub_count, BPF_ANY);

    if (gs->sub_count == 1) {
        /* Find the remaining subscriber and restore fast path */
        for (uint32_t s = 0; s < MAX_SUBS; s++) {
            if (gs->slot_used[s]) {
                bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_single_if),
                                    &gid, &gs->slot_ifindex[s], BPF_ANY);
                break;
            }
        }
        /* Drop back from AF-XDP path if we were above threshold */
        afxdp_deactivate_group(gs);
    } else if (gs->sub_count == 0) {
        afxdp_deactivate_group(gs);
        uint32_t zero = 0;
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_single_if),
                            &gid, &zero, BPF_ANY);
    }
}

/* ── Ring buffer event handler ─────────────────────────────────────────── */

static int handle_event(void *ctx_unused, void *data, size_t data_sz)
{
    (void)ctx_unused;
    if (data_sz < sizeof(struct event))
        return 0;

    const struct event *e = data;
    uint32_t group_addr   = e->group;
    uint32_t ifindex      = e->ifindex;

    if (e->type == EVENT_JOIN) {
        struct group_state *gs = find_group(group_addr);

        if (!gs) {
            /* First subscriber for this group — allocate slot */
            gs = alloc_group_slot();
            if (!gs) {
                fprintf(stderr, "handle_event: group table full\n");
                return 0;
            }
            gs->group_addr = group_addr;

            /*
             * For group_id 0, the inner devmap is inner_devmap_proto which
             * was pre-allocated by libbpf at skeleton load time.  For ids
             * 1..255 we create a fresh inner devmap and insert it into the
             * ARRAY_OF_MAPS outer map.
             */
            if (gs->group_id == 0) {
                gs->devmap_fd = bpf_map__fd(g_skel->maps.inner_devmap_proto);
            } else {
                gs->devmap_fd = create_inner_devmap();
                if (gs->devmap_fd < 0) {
                    fprintf(stderr,
                            "handle_event: create_inner_devmap failed: %s\n",
                            strerror(errno));
                    memset(gs, 0, sizeof(*gs));
                    return 0;
                }
                /* Insert new inner map into the ARRAY_OF_MAPS */
                uint32_t gid = gs->group_id;
                bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_map),
                                    &gid, &gs->devmap_fd, BPF_ANY);
            }

            /* Register group_addr → group_id in the BPF hash map */
            uint32_t gid = gs->group_id;
            bpf_map_update_elem(bpf_map__fd(g_skel->maps.group_id_map),
                                &group_addr, &gid, BPF_ANY);

            /* Issue upstream IGMP membership report */
            igmp_join(gs);
        }

        group_add_subscriber(gs, ifindex);

        fprintf(stderr, "join: group=%s ifindex=%u subs=%u\n",
                group_str(group_addr), ifindex, gs->sub_count);

    } else if (e->type == EVENT_LEAVE) {
        struct group_state *gs = find_group(group_addr);
        if (!gs)
            return 0;

        group_remove_subscriber(gs, ifindex);

        fprintf(stderr, "leave: group=%s ifindex=%u subs=%u\n",
                group_str(group_addr), ifindex, gs->sub_count);

        if (gs->sub_count == 0) {
            /* Last subscriber gone — send IGMP leave upstream */
            igmp_leave(gs);

            /* Remove from group_id_map so XDP passes the stream to kernel */
            bpf_map_delete_elem(bpf_map__fd(g_skel->maps.group_id_map),
                                &group_addr);

            /* Release inner devmap (not for slot 0 — proto is owned by skel) */
            if (gs->group_id != 0)
                close(gs->devmap_fd);

            memset(gs, 0, sizeof(*gs));
        }
    }

    return 0;
}

/* ── XDP downstream attach / detach ────────────────────────────────────── */

/*
 * attach_downstream — attach xdp_downstream (L2) or xdp_downstream_l3 (L3)
 * to a container's host-side interface, selected by l3_mode.
 *
 * l3_mode == IFACE_L2_MODE: veth or netkit-L2 — Ethernet header is present.
 * l3_mode == IFACE_L3_MODE: netkit-L3         — packet starts at IP header.
 *
 * Uses DRV (native XDP) mode for lowest latency; falls back to SKB mode on
 * drivers that do not support native XDP (e.g. virtio in test environments).
 */
static int attach_downstream(uint32_t ifindex, int l3_mode)
{
    pthread_mutex_lock(&g_iface_lock);

    /* Idempotent: skip if already attached */
    for (int i = 0; i < g_n_ifaces; i++) {
        if (g_ifaces[i].ifindex == ifindex) {
            pthread_mutex_unlock(&g_iface_lock);
            return 0;
        }
    }
    if (g_n_ifaces >= MAX_SUBS) {
        pthread_mutex_unlock(&g_iface_lock);
        return -ENOSPC;
    }

    /*
     * Select the BPF program matching the interface's L2/L3 mode.
     * xdp_downstream     — parses ethhdr then IP (veth, netkit-L2).
     * xdp_downstream_l3  — parses IP directly (netkit-L3, no ethhdr).
     */
    int prog_fd = (l3_mode == IFACE_L3_MODE)
                  ? bpf_program__fd(g_skel->progs.xdp_downstream_l3)
                  : bpf_program__fd(g_skel->progs.xdp_downstream);

    int used_flags = XDP_FLAGS_DRV_MODE;
    int err        = bpf_xdp_attach(ifindex, prog_fd, used_flags, NULL);
    if (err < 0) {
        used_flags = XDP_FLAGS_SKB_MODE;
        err        = bpf_xdp_attach(ifindex, prog_fd, used_flags, NULL);
    }
    if (err < 0) {
        fprintf(stderr,
                "attach_downstream: ifindex=%u l3=%d failed: %s\n",
                ifindex, l3_mode, strerror(-err));
        pthread_mutex_unlock(&g_iface_lock);
        return err;
    }

    g_ifaces[g_n_ifaces].ifindex   = ifindex;
    g_ifaces[g_n_ifaces].link_fd   = -1;
    g_ifaces[g_n_ifaces].xdp_flags = used_flags;
    g_ifaces[g_n_ifaces].l3_mode   = l3_mode;
    g_n_ifaces++;

    pthread_mutex_unlock(&g_iface_lock);
    fprintf(stderr,
            "xdp_downstream%s attached to ifindex=%u (flags=%s)\n",
            l3_mode == IFACE_L3_MODE ? "_l3" : "",
            ifindex,
            used_flags == XDP_FLAGS_DRV_MODE ? "drv" : "skb");
    return 0;
}

static void detach_downstream(uint32_t ifindex)
{
    pthread_mutex_lock(&g_iface_lock);

    for (int i = 0; i < g_n_ifaces; i++) {
        if (g_ifaces[i].ifindex != ifindex)
            continue;

        /* Detach using the exact flags recorded at attach time */
        bpf_xdp_detach(ifindex, g_ifaces[i].xdp_flags, NULL);

        g_n_ifaces--;
        if (i < g_n_ifaces)
            g_ifaces[i] = g_ifaces[g_n_ifaces];
        break;
    }

    pthread_mutex_unlock(&g_iface_lock);

    /* Trigger leave for all groups this interface was subscribed to */
    for (int g = 0; g < MAX_GROUPS; g++) {
        struct group_state *gs = &g_groups[g];
        if (gs->sub_count == 0) continue;
        for (uint32_t s = 0; s < MAX_SUBS; s++) {
            if (gs->slot_used[s] && gs->slot_ifindex[s] == ifindex) {
                struct event fake = {
                    .type    = EVENT_LEAVE,
                    .group   = gs->group_addr,
                    .ifindex = ifindex,
                };
                handle_event(NULL, &fake, sizeof(fake));
                break;
            }
        }
    }

    fprintf(stderr, "xdp_downstream detached from ifindex=%u\n", ifindex);
}

/* ── Link-type detection ─────────────────────────────────────────────────
 *
 * Parses IFLA_LINKINFO sub-attributes from a set of RTAs already extracted
 * from a RTM_NEWLINK message or a RTM_GETLINK response.
 *
 * On return:
 *   kind_out  — filled with the IFLA_INFO_KIND string, e.g. "veth", "netkit"
 *   l3_mode_out — set to IFACE_L3_MODE if kind=="netkit" and the netkit mode
 *                 attribute is NETKIT_L3; IFACE_L2_MODE otherwise.
 */
static void parse_link_attrs(struct rtattr *rta, int rta_len,
                              char *kind_out, int *l3_mode_out)
{
    kind_out[0]  = '\0';
    *l3_mode_out = IFACE_L2_MODE;

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        if (rta->rta_type != IFLA_LINKINFO)
            continue;

        /* Level 2: IFLA_LINKINFO sub-attributes */
        struct rtattr *li     = (struct rtattr *)RTA_DATA(rta);
        int            li_len = (int)RTA_PAYLOAD(rta);

        for (; RTA_OK(li, li_len); li = RTA_NEXT(li, li_len)) {
            if (li->rta_type == IFLA_INFO_KIND) {
                strncpy(kind_out, (char *)RTA_DATA(li), 15);
                kind_out[15] = '\0';

            } else if (li->rta_type == IFLA_INFO_DATA) {
                /* Level 3: link-type-specific attributes */
                struct rtattr *ld     = (struct rtattr *)RTA_DATA(li);
                int            ld_len = (int)RTA_PAYLOAD(li);

                for (; RTA_OK(ld, ld_len); ld = RTA_NEXT(ld, ld_len)) {
                    if (ld->rta_type == IFLA_NETKIT_MODE) {
                        uint32_t mode = 0;
                        if (RTA_PAYLOAD(ld) >= sizeof(mode))
                            memcpy(&mode, RTA_DATA(ld), sizeof(mode));
                        *l3_mode_out = (mode == NETKIT_L3)
                                       ? IFACE_L3_MODE : IFACE_L2_MODE;
                    }
                }
            }
        }
    }
}

/*
 * query_link_type — send a RTM_GETLINK request for ifindex and fill
 *                   kind_out / l3_mode_out from the IFLA_LINKINFO reply.
 *
 * Used at startup enumeration when no RTM_NEWLINK notification is available.
 * Returns 0 on success, -errno on failure.
 */
static int query_link_type(uint32_t ifindex, char *kind_out, int *l3_mode_out)
{
    kind_out[0]  = '\0';
    *l3_mode_out = IFACE_L2_MODE;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return -errno;

    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
    } req = {
        .nlh = {
            .nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .nlmsg_type  = RTM_GETLINK,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq   = 1,
        },
        .ifi = {
            .ifi_family = AF_UNSPEC,
            .ifi_index  = (int)ifindex,
        },
    };

    if (send(fd, &req, sizeof(req), 0) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    char buf[8192];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    close(fd);

    if (n < 0)
        return -errno;

    for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
         NLMSG_OK(nh, (unsigned int)n);
         nh = NLMSG_NEXT(nh, n)) {

        if (nh->nlmsg_type == NLMSG_ERROR || nh->nlmsg_type == NLMSG_DONE)
            break;
        if (nh->nlmsg_type != RTM_NEWLINK)
            continue;

        struct ifinfomsg *ifi = NLMSG_DATA(nh);
        if ((uint32_t)ifi->ifi_index != ifindex)
            continue;

        struct rtattr *rta     = IFLA_RTA(ifi);
        int            rta_len = (int)(nh->nlmsg_len
                                       - NLMSG_SPACE(sizeof(*ifi)));
        parse_link_attrs(rta, rta_len, kind_out, l3_mode_out);
        return 0;
    }

    return -ENODEV;
}

/*
 * is_container_kind — returns 1 if the IFLA_INFO_KIND string identifies an
 * interface type used as a container peer (veth or netkit).
 * If kind is empty (older kernel / unusual driver), fall back to name pattern.
 */
static int is_container_kind(const char *kind, const char *ifname)
{
    if (kind[0] != '\0')
        return (strcmp(kind, "veth")   == 0 ||
                strcmp(kind, "netkit") == 0);

    /* Fallback: name-pattern heuristic when kind is unavailable */
    return (strncmp(ifname, "veth", 4) == 0 ||
            strncmp(ifname, "lxc",  3) == 0 ||
            strncmp(ifname, "nk-",  3) == 0 ||
            strncmp(ifname, "cali", 4) == 0);
}

/* ── Netlink interface watcher ─────────────────────────────────────────── */

static void *netlink_watch_thread(void *arg)
{
    (void)arg;

    int nlfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nlfd < 0) {
        perror("netlink: socket");
        return NULL;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK,
    };
    if (bind(nlfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("netlink: bind");
        close(nlfd);
        return NULL;
    }

    char buf[8192];
    while (g_running) {
        ssize_t n = recv(nlfd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
             NLMSG_OK(nh, (unsigned int)n);
             nh = NLMSG_NEXT(nh, n)) {

            if (nh->nlmsg_type == NLMSG_DONE)
                break;
            if (nh->nlmsg_type == NLMSG_ERROR)
                continue;

            if (nh->nlmsg_type == RTM_NEWLINK ||
                nh->nlmsg_type == RTM_DELLINK) {

                struct ifinfomsg *ifi     = NLMSG_DATA(nh);
                char              ifname[IFNAMSIZ] = {};
                char              kind[16]          = {};
                int               l3_mode           = IFACE_L2_MODE;

                struct rtattr *rta     = IFLA_RTA(ifi);
                int            rta_len = (int)(nh->nlmsg_len
                                               - NLMSG_SPACE(sizeof(*ifi)));

                /* Single pass: extract IFLA_IFNAME and IFLA_LINKINFO */
                for (struct rtattr *a = rta; RTA_OK(a, rta_len);
                     a = RTA_NEXT(a, rta_len)) {
                    if (a->rta_type == IFLA_IFNAME)
                        strncpy(ifname, (char *)RTA_DATA(a),
                                sizeof(ifname) - 1);
                }
                /* parse_link_attrs handles nested IFLA_LINKINFO walk */
                parse_link_attrs(rta, rta_len, kind, &l3_mode);

                if (!ifname[0])
                    continue;

                if (nh->nlmsg_type == RTM_NEWLINK &&
                    (ifi->ifi_flags & IFF_UP) &&
                    (uint32_t)ifi->ifi_index != (uint32_t)g_uplink_ifindex &&
                    strcmp(ifname, "lo") != 0 &&
                    is_container_kind(kind, ifname)) {

                    attach_downstream((uint32_t)ifi->ifi_index, l3_mode);
                }

                if (nh->nlmsg_type == RTM_DELLINK) {
                    detach_downstream((uint32_t)ifi->ifi_index);
                }
            }
        }
    }

    close(nlfd);
    return NULL;
}

/* ── Enumerate existing interfaces at startup ──────────────────────────── */

static void enumerate_existing_ifaces(void)
{
    struct if_nameindex *ifaces = if_nameindex();
    if (!ifaces)
        return;

    for (int i = 0; ifaces[i].if_index != 0; i++) {
        uint32_t ifindex = ifaces[i].if_index;
        const char *name = ifaces[i].if_name;

        if (ifindex == (uint32_t)g_uplink_ifindex) continue;
        if (strcmp(name, "lo") == 0)               continue;

        char kind[16] = {};
        int  l3_mode  = IFACE_L2_MODE;

        /*
         * query_link_type sends RTM_GETLINK for this ifindex and parses
         * IFLA_INFO_KIND + IFLA_NETKIT_MODE from the kernel response.
         * This is the authoritative detection path used at startup; the
         * netlink watcher uses parse_link_attrs() on the live notification.
         */
        if (query_link_type(ifindex, kind, &l3_mode) < 0) {
            /* RTM_GETLINK failed (interface vanished) — skip */
            continue;
        }

        if (is_container_kind(kind, name))
            attach_downstream(ifindex, l3_mode);
    }

    if_freenameindex(ifaces);
}

/* ── BPF load and attach ────────────────────────────────────────────────── */

static int load_and_attach_bpf(void)
{
    g_skel = multicast_bpf__open_and_load();
    if (!g_skel) {
        fprintf(stderr, "bpf: open_and_load failed\n");
        return -1;
    }

    g_egress_prog_fd = bpf_program__fd(g_skel->progs.xdp_devmap_egress);

    /* Attach xdp_upstream to uplink */
    g_uplink_ifindex = (int)if_nametoindex(g_uplink);
    if (!g_uplink_ifindex) {
        fprintf(stderr, "bpf: interface %s not found\n", g_uplink);
        return -1;
    }

    int upstream_fd = bpf_program__fd(g_skel->progs.xdp_upstream);
    int err = bpf_xdp_attach(g_uplink_ifindex, upstream_fd,
                             XDP_FLAGS_DRV_MODE, NULL);
    if (err < 0) {
        err = bpf_xdp_attach(g_uplink_ifindex, upstream_fd,
                             XDP_FLAGS_SKB_MODE, NULL);
    }
    if (err < 0) {
        fprintf(stderr, "bpf: attach xdp_upstream to %s failed: %s\n",
                g_uplink, strerror(-err));
        return err;
    }

    fprintf(stderr, "bpf: xdp_upstream attached to %s (ifindex=%d)\n",
            g_uplink, g_uplink_ifindex);
    return 0;
}

static void detach_uplink(void)
{
    if (g_uplink_ifindex <= 0) return;
    bpf_xdp_detach(g_uplink_ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(g_uplink_ifindex, XDP_FLAGS_SKB_MODE, NULL);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    const char *env;

    (void)argc; (void)argv;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Configuration from environment variables */
    if ((env = getenv("UPLINK_IFACE")) != NULL)
        strncpy(g_uplink, env, IFNAMSIZ - 1);

    fprintf(stderr, "igmp-proxy: starting, uplink=%s\n", g_uplink);

    /* Load and attach BPF programs */
    if (load_and_attach_bpf() < 0)
        return 1;

    /* Initialise AF-XDP context (Tier 3) */
    {
        int q = 0;
        if ((env = getenv("XSK_QUEUE_ID")) != NULL)
            q = atoi(env);
        int xsk_map_fd = bpf_map__fd(g_skel->maps.xsk_map);
        if (afxdp_init(&g_afxdp, g_uplink, q, xsk_map_fd) == 0) {
            g_afxdp_active = 1;
            fprintf(stderr, "igmp-proxy: AF-XDP path ready\n");
        } else {
            fprintf(stderr, "igmp-proxy: AF-XDP init failed, Tier-3 disabled\n");
        }
    }

    /* Set up ring buffer reader */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(g_skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        return 1;
    }

    /* Enumerate existing container interfaces */
    enumerate_existing_ifaces();

    /* Start netlink watcher thread */
    pthread_t nl_tid;
    pthread_create(&nl_tid, NULL, netlink_watch_thread, NULL);

    fprintf(stderr, "igmp-proxy: running\n");

    /* Main event loop: drain ring buffer */
    while (g_running) {
        int err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0 && err != -EINTR)
            break;
    }

    fprintf(stderr, "igmp-proxy: shutting down\n");

    /* Cleanup */
    g_running = 0;
    pthread_join(nl_tid, NULL);
    ring_buffer__free(rb);

    /* Send IGMP leaves for all active groups */
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (g_groups[i].igmp_sock >= 0)
            igmp_leave(&g_groups[i]);
    }

    detach_uplink();

    /* Detach all container interfaces using the flags recorded at attach time */
    pthread_mutex_lock(&g_iface_lock);
    for (int i = 0; i < g_n_ifaces; i++)
        bpf_xdp_detach(g_ifaces[i].ifindex, g_ifaces[i].xdp_flags, NULL);
    pthread_mutex_unlock(&g_iface_lock);

    if (g_afxdp_active)
        afxdp_destroy(&g_afxdp);

    multicast_bpf__destroy(g_skel);
    return 0;
}
