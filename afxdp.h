#ifndef AFXDP_H
#define AFXDP_H

/*
 * Tier-3: AF_XDP shared UMEM zero-copy multicast delivery.
 *
 * Architecture:
 *   - One UMEM region (huge-page backed) shared across all subscribers.
 *   - NIC DMA writes packet data once into UMEM — never copied again.
 *   - XDP redirects the arriving multicast packet to the aggregator XSK
 *     (slot 0 in xsk_map) via bpf_redirect_map().
 *   - The dispatch thread reads from the aggregator XSK's RX ring, then
 *     for each active subscriber writes just the 8-byte UMEM descriptor
 *     {addr, len} to that subscriber's shadow RX ring.
 *   - Subscribers read their shadow ring and access packet data in shared
 *     UMEM directly — zero additional data copies.
 *   - Per-frame reference counting ensures UMEM frames are only recycled
 *     to the fill ring after every subscriber has signalled completion.
 *
 * Crossover point: cheaper than devmap broadcast when N > AFXDP_SUB_THRESHOLD
 * because (N-1)×memcpy cost exceeds the descriptor-write overhead.
 */

#include <stdint.h>
#include <pthread.h>
#include <xdp/xsk.h>

#define UMEM_NUM_FRAMES     4096
#define UMEM_FRAME_SIZE     XSK_UMEM__DEFAULT_FRAME_SIZE   /* 4096 bytes */
#define UMEM_SIZE           ((uint64_t)UMEM_NUM_FRAMES * UMEM_FRAME_SIZE)
#define XSK_RING_SIZE       2048   /* must be power of two */

/*
 * Shadow RX ring — written by dispatch thread, read by subscriber.
 * Lock-free single-producer / single-consumer (SPSC).
 */
#define SHADOW_RING_SIZE    1024   /* must be power of two */
#define SHADOW_RING_MASK    (SHADOW_RING_SIZE - 1)

struct shadow_desc {
    uint64_t addr;   /* UMEM frame address (offset into umem_area) */
    uint32_t len;    /* valid bytes */
    uint32_t _pad;
};

struct shadow_ring {
    struct shadow_desc descs[SHADOW_RING_SIZE];
    volatile uint32_t  prod __attribute__((aligned(64)));
    volatile uint32_t  cons __attribute__((aligned(64)));
};

/* Per-subscriber state */
struct xsk_sub {
    struct xsk_socket      *xsk;
    struct xsk_ring_prod    fq;   /* fill queue (shared UMEM) */
    struct xsk_ring_cons    cq;   /* completion queue          */
    struct shadow_ring     *srx;  /* shadow RX for zero-copy fanout */
    uint32_t                container_ifindex;
    int                     xsk_map_slot;
    volatile int            active;
};

/* Global AF_XDP context — one instance per node, shared across groups */
struct afxdp_ctx {
    /* UMEM */
    void                *umem_area;   /* mmap'd memory, huge-page backed  */
    struct xsk_umem     *umem;
    struct xsk_ring_prod fq;          /* primary fill queue               */
    struct xsk_ring_cons cq;          /* primary completion queue         */

    /* Per-frame refcount: decremented when each subscriber returns frame */
    volatile uint32_t    refcnt[UMEM_NUM_FRAMES];

    /* Aggregator XSK: receives multicast packets from XDP redirect */
    struct xsk_socket   *agg_xsk;
    struct xsk_ring_cons agg_rx;

    /* Subscriber table */
    struct xsk_sub       subs[128];
    int                  nsubs;
    pthread_mutex_t      subs_lock;

    /* xsk_map fd (BPF map) */
    int                  xsk_map_fd;

    /* Dispatch thread */
    pthread_t            dispatch_tid;
    volatile int         running;

    char                 ifname[16];  /* uplink interface name */
};

/*
 * afxdp_init — allocate UMEM, create aggregator XSK, populate fill ring,
 *              start dispatch thread.  Returns 0 on success.
 *
 * @ctx:         pre-allocated context struct (zeroed by caller)
 * @ifname:      uplink interface name (e.g. "eth0")
 * @queue_id:    RX queue index on the uplink that XDP will redirect to
 * @xsk_map_fd:  fd of the xsk_map BPF map
 */
int  afxdp_init(struct afxdp_ctx *ctx, const char *ifname,
                int queue_id, int xsk_map_fd);

/*
 * afxdp_add_subscriber — create a shared-UMEM XSK for a new container,
 *                        register it in xsk_map, allocate shadow ring.
 *                        Returns xsk_map_slot (≥0) on success, -errno on error.
 *
 * @ctx:                  initialised context
 * @container_ifindex:    host-side ifindex of the container's netkit/veth peer
 */
int  afxdp_add_subscriber(struct afxdp_ctx *ctx, uint32_t container_ifindex);

/*
 * afxdp_remove_subscriber — deregister from xsk_map, free shadow ring,
 *                           destroy XSK socket.
 */
void afxdp_remove_subscriber(struct afxdp_ctx *ctx, uint32_t container_ifindex);

/*
 * afxdp_destroy — stop dispatch thread, destroy all XSKs and UMEM.
 */
void afxdp_destroy(struct afxdp_ctx *ctx);

/* Dispatch thread entry — passed to pthread_create; arg = struct afxdp_ctx* */
void *afxdp_dispatch_loop(void *arg);

#endif /* AFXDP_H */
