// SPDX-License-Identifier: GPL-2.0
/*
 * Tier-3 AF_XDP shared UMEM implementation.
 *
 * One UMEM region is allocated with huge-page backing.  An "aggregator" XSK
 * socket receives all multicast packets redirected by xdp_upstream via the
 * xsk_map.  The dispatch thread reads from the aggregator RX ring and fans
 * out 8-byte descriptors (addr + len, no data copy) to each subscriber's
 * shadow ring.  Subscribers read from the shadow ring and access packet data
 * directly in the shared UMEM region.
 *
 * Per-frame reference counting drives UMEM frame recycling back to the fill
 * ring only after every subscriber has consumed the frame.
 */

#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "afxdp.h"

/* ── UMEM helpers ──────────────────────────────────────────────────────── */

static inline uint32_t frame_idx(struct afxdp_ctx *ctx, uint64_t addr)
{
    return (uint32_t)(addr / UMEM_FRAME_SIZE);
}

/* Atomically decrement refcount; returns new value */
static inline uint32_t frame_unref(struct afxdp_ctx *ctx, uint64_t addr)
{
    uint32_t idx = frame_idx(ctx, addr);
    return __atomic_sub_fetch(&ctx->refcnt[idx], 1, __ATOMIC_RELEASE);
}

static inline void frame_ref_set(struct afxdp_ctx *ctx, uint64_t addr,
                                 uint32_t count)
{
    uint32_t idx = frame_idx(ctx, addr);
    __atomic_store_n(&ctx->refcnt[idx], count, __ATOMIC_RELEASE);
}

/* ── Shadow ring ───────────────────────────────────────────────────────── */

static struct shadow_ring *shadow_ring_alloc(void)
{
    struct shadow_ring *r = aligned_alloc(64, sizeof(*r));
    if (r) {
        memset(r, 0, sizeof(*r));
    }
    return r;
}

/* Producer: returns 1 if slot was available and desc was written */
static int shadow_ring_push(struct shadow_ring *r,
                            uint64_t addr, uint32_t len)
{
    uint32_t prod = r->prod;
    uint32_t cons = __atomic_load_n(&r->cons, __ATOMIC_ACQUIRE);
    if ((prod - cons) >= SHADOW_RING_SIZE)
        return 0;  /* ring full — subscriber too slow, frame will be dropped */

    uint32_t slot     = prod & SHADOW_RING_MASK;
    r->descs[slot].addr = addr;
    r->descs[slot].len  = len;
    __atomic_store_n(&r->prod, prod + 1, __ATOMIC_RELEASE);
    return 1;
}

/* Consumer: returns 1 if a descriptor was read */
int shadow_ring_pop(struct shadow_ring *r, uint64_t *addr, uint32_t *len)
{
    uint32_t cons = r->cons;
    uint32_t prod = __atomic_load_n(&r->prod, __ATOMIC_ACQUIRE);
    if (cons == prod)
        return 0;

    uint32_t slot = cons & SHADOW_RING_MASK;
    *addr = r->descs[slot].addr;
    *len  = r->descs[slot].len;
    __atomic_store_n(&r->cons, cons + 1, __ATOMIC_RELEASE);
    return 1;
}

/* ── UMEM initialisation ───────────────────────────────────────────────── */

static int umem_create(struct afxdp_ctx *ctx)
{
    /*
     * Allocate UMEM with huge-page backing to minimise TLB pressure at
     * the high packet rates this path is designed for.
     */
    ctx->umem_area = mmap(NULL, UMEM_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);
    if (ctx->umem_area == MAP_FAILED) {
        /* Fallback: regular pages */
        ctx->umem_area = mmap(NULL, UMEM_SIZE,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS,
                              -1, 0);
        if (ctx->umem_area == MAP_FAILED) {
            perror("mmap UMEM");
            return -errno;
        }
        fprintf(stderr, "afxdp: huge pages unavailable, using regular pages\n");
    }

    /* Advise the kernel to keep these pages resident */
    madvise(ctx->umem_area, UMEM_SIZE, MADV_DONTFORK);

    struct xsk_umem_config cfg = {
        .fill_size      = XSK_RING_SIZE,
        .comp_size      = XSK_RING_SIZE,
        .frame_size     = UMEM_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };

    int err = xsk_umem__create(&ctx->umem, ctx->umem_area, UMEM_SIZE,
                               &ctx->fq, &ctx->cq, &cfg);
    if (err) {
        fprintf(stderr, "afxdp: xsk_umem__create failed: %s\n", strerror(-err));
        munmap(ctx->umem_area, UMEM_SIZE);
        return err;
    }

    /* Pre-populate fill queue with all frames */
    uint32_t idx;
    uint32_t reserved = xsk_ring_prod__reserve(&ctx->fq,
                                               UMEM_NUM_FRAMES / 2, &idx);
    for (uint32_t i = 0; i < reserved; i++)
        *xsk_ring_prod__fill_addr(&ctx->fq, idx + i) =
            (uint64_t)(i * UMEM_FRAME_SIZE);
    xsk_ring_prod__submit(&ctx->fq, reserved);

    return 0;
}

/* ── Aggregator XSK ────────────────────────────────────────────────────── */

static int agg_xsk_create(struct afxdp_ctx *ctx, int queue_id)
{
    struct xsk_socket_config cfg = {
        .rx_size      = XSK_RING_SIZE,
        .tx_size      = XSK_RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags    = 0,
        .bind_flags   = 0,
    };

    int err = xsk_socket__create(&ctx->agg_xsk, ctx->ifname, queue_id,
                                 ctx->umem, &ctx->agg_rx, NULL, &cfg);
    if (err) {
        fprintf(stderr, "afxdp: aggregator xsk_socket__create failed: %s\n",
                strerror(-err));
        return err;
    }

    /* Register aggregator XSK in slot 0 of xsk_map */
    int fd  = xsk_socket__fd(ctx->agg_xsk);
    int key = 0;
    err = bpf_map_update_elem(ctx->xsk_map_fd, &key, &fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "afxdp: failed to register agg XSK in xsk_map: %s\n",
                strerror(errno));
        xsk_socket__delete(ctx->agg_xsk);
        ctx->agg_xsk = NULL;
        return -errno;
    }

    return 0;
}

/* ── Public API ────────────────────────────────────────────────────────── */

int afxdp_init(struct afxdp_ctx *ctx, const char *ifname,
               int queue_id, int xsk_map_fd)
{
    memset(ctx, 0, sizeof(*ctx));
    strncpy(ctx->ifname, ifname, sizeof(ctx->ifname) - 1);
    ctx->xsk_map_fd = xsk_map_fd;
    pthread_mutex_init(&ctx->subs_lock, NULL);

    int err = umem_create(ctx);
    if (err)
        return err;

    err = agg_xsk_create(ctx, queue_id);
    if (err) {
        xsk_umem__delete(ctx->umem);
        munmap(ctx->umem_area, UMEM_SIZE);
        return err;
    }

    ctx->running = 1;
    err = pthread_create(&ctx->dispatch_tid, NULL, afxdp_dispatch_loop, ctx);
    if (err) {
        fprintf(stderr, "afxdp: pthread_create failed: %s\n", strerror(err));
        ctx->running = 0;
        xsk_socket__delete(ctx->agg_xsk);
        xsk_umem__delete(ctx->umem);
        munmap(ctx->umem_area, UMEM_SIZE);
        return -err;
    }

    fprintf(stderr, "afxdp: initialised on %s queue %d, UMEM %zu MB\n",
            ifname, queue_id, UMEM_SIZE >> 20);
    return 0;
}

int afxdp_add_subscriber(struct afxdp_ctx *ctx, uint32_t container_ifindex)
{
    pthread_mutex_lock(&ctx->subs_lock);

    if (ctx->nsubs >= (int)(sizeof(ctx->subs) / sizeof(ctx->subs[0]))) {
        pthread_mutex_unlock(&ctx->subs_lock);
        return -ENOSPC;
    }

    /* Find a free slot in xsk_map (slot 0 is the aggregator) */
    int slot = -1;
    for (int i = 1; i < 128; i++) {
        int found = 0;
        for (int j = 0; j < ctx->nsubs; j++) {
            if (ctx->subs[j].xsk_map_slot == i) { found = 1; break; }
        }
        if (!found) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&ctx->subs_lock);
        return -ENOSPC;
    }

    struct xsk_sub *sub = &ctx->subs[ctx->nsubs];
    memset(sub, 0, sizeof(*sub));

    sub->srx = shadow_ring_alloc();
    if (!sub->srx) {
        pthread_mutex_unlock(&ctx->subs_lock);
        return -ENOMEM;
    }

    /*
     * Create a socket sharing the existing UMEM.  XDP_SHARED_UMEM allows
     * multiple sockets to share one UMEM region, so the packet written once
     * by the NIC DMA is accessible to all subscribers without copying.
     */
    struct xsk_socket_config cfg = {
        .rx_size      = XSK_RING_SIZE,
        .tx_size      = 0,            /* subscribers don't TX */
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags    = 0,
        .bind_flags   = XDP_SHARED_UMEM,
    };

    int err = xsk_socket__create_shared(&sub->xsk, ctx->ifname,
                                        0 /* queue_id */,
                                        ctx->umem,
                                        NULL /* no rx ring — shadow ring used */,
                                        NULL,
                                        &sub->fq, &sub->cq,
                                        &cfg);
    if (err) {
        fprintf(stderr, "afxdp: xsk_socket__create_shared failed: %s\n",
                strerror(-err));
        free(sub->srx);
        pthread_mutex_unlock(&ctx->subs_lock);
        return err;
    }

    /* Register subscriber fd in xsk_map so XDP can redirect to it */
    int fd = xsk_socket__fd(sub->xsk);
    err = bpf_map_update_elem(ctx->xsk_map_fd, &slot, &fd, BPF_ANY);
    if (err) {
        xsk_socket__delete(sub->xsk);
        free(sub->srx);
        pthread_mutex_unlock(&ctx->subs_lock);
        return -errno;
    }

    sub->container_ifindex = container_ifindex;
    sub->xsk_map_slot      = slot;
    __atomic_store_n(&sub->active, 1, __ATOMIC_RELEASE);
    ctx->nsubs++;

    pthread_mutex_unlock(&ctx->subs_lock);

    fprintf(stderr, "afxdp: added subscriber ifindex=%u at xsk_map slot %d\n",
            container_ifindex, slot);
    return slot;
}

void afxdp_remove_subscriber(struct afxdp_ctx *ctx, uint32_t container_ifindex)
{
    pthread_mutex_lock(&ctx->subs_lock);

    for (int i = 0; i < ctx->nsubs; i++) {
        struct xsk_sub *sub = &ctx->subs[i];
        if (sub->container_ifindex != container_ifindex)
            continue;

        /* Mark inactive so dispatch loop skips it immediately */
        __atomic_store_n(&sub->active, 0, __ATOMIC_RELEASE);

        /* Remove from xsk_map */
        bpf_map_delete_elem(ctx->xsk_map_fd, &sub->xsk_map_slot);

        xsk_socket__delete(sub->xsk);
        free(sub->srx);

        /* Compact the table */
        ctx->nsubs--;
        if (i < ctx->nsubs)
            ctx->subs[i] = ctx->subs[ctx->nsubs];
        memset(&ctx->subs[ctx->nsubs], 0, sizeof(ctx->subs[ctx->nsubs]));
        break;
    }

    pthread_mutex_unlock(&ctx->subs_lock);
}

void afxdp_destroy(struct afxdp_ctx *ctx)
{
    ctx->running = 0;
    pthread_join(ctx->dispatch_tid, NULL);

    pthread_mutex_lock(&ctx->subs_lock);
    for (int i = 0; i < ctx->nsubs; i++) {
        bpf_map_delete_elem(ctx->xsk_map_fd, &ctx->subs[i].xsk_map_slot);
        xsk_socket__delete(ctx->subs[i].xsk);
        free(ctx->subs[i].srx);
    }
    ctx->nsubs = 0;
    pthread_mutex_unlock(&ctx->subs_lock);

    /* Remove aggregator */
    int key = 0;
    bpf_map_delete_elem(ctx->xsk_map_fd, &key);
    xsk_socket__delete(ctx->agg_xsk);

    xsk_umem__delete(ctx->umem);
    munmap(ctx->umem_area, UMEM_SIZE);
    pthread_mutex_destroy(&ctx->subs_lock);
}

/*
 * Number of consecutive empty RX polls before the dispatch thread gives up
 * busy-polling and blocks in poll(2).  Each iteration is ~50–100 ns, so 64
 * spins ≈ 3–6 µs of busy-wait before sleeping.  On the first packet after
 * an idle period the worst-case wake latency is the poll() timeout (1 ms);
 * under sustained load the counter never reaches the threshold so latency
 * stays in the 1–2 µs busy-poll range.
 */
#define BUSY_POLL_BUDGET 64

/* ── Dispatch loop ─────────────────────────────────────────────────────────
 *
 * Runs on a dedicated thread, busy-polling the aggregator XSK RX ring.
 * For each arriving multicast packet:
 *   1. Set frame refcount to nsubs (one reference per active subscriber).
 *   2. Write UMEM descriptor (addr + len) to each subscriber's shadow ring.
 *      This is 8 bytes written per subscriber — no packet data is copied.
 *   3. Subscribers read their shadow ring and access UMEM[addr] directly.
 *   4. When a subscriber is done, it calls afxdp_frame_release() which
 *      decrements the refcount; on reaching 0 the frame is recycled to the
 *      fill ring so the NIC can DMA the next packet into it.
 *
 * Hybrid idle strategy: spin for BUSY_POLL_BUDGET empty batches (~3–6 µs),
 * then block in poll(2) with a 1 ms timeout.  Under load the budget is never
 * exhausted, preserving ~1–2 µs dispatch latency.  When idle, the thread
 * sleeps and burns no CPU.
 */
void *afxdp_dispatch_loop(void *arg)
{
    struct afxdp_ctx *ctx = arg;
    int xsk_fd = xsk_socket__fd(ctx->agg_xsk);
    int idle   = 0;

    /* Recycle frames whose refcount reached 0 back to the fill queue */
    uint64_t recycle_queue[UMEM_NUM_FRAMES];
    int      recycle_head = 0, recycle_tail = 0;

    while (ctx->running) {
        uint32_t rx_idx = 0;
        uint32_t rcvd   = xsk_ring_cons__peek(&ctx->agg_rx, 32, &rx_idx);

        if (!rcvd) {
            if (++idle < BUSY_POLL_BUDGET)
                continue;  /* still in busy-poll window */

            /* Budget exhausted — sleep until a packet (or 1 ms) wakes us */
            struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
            poll(&pfd, 1, 1);
            idle = 0;
            continue;
        }

        idle = 0;

        pthread_mutex_lock(&ctx->subs_lock);
        int nsubs = ctx->nsubs;

        for (uint32_t i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc =
                xsk_ring_cons__rx_desc(&ctx->agg_rx, rx_idx + i);
            uint64_t addr = desc->addr;
            uint32_t len  = desc->len;

            if (nsubs == 0) {
                /* No subscribers: recycle immediately */
                recycle_queue[recycle_tail++ % UMEM_NUM_FRAMES] = addr;
                continue;
            }

            /* Set refcount to number of active subscribers */
            frame_ref_set(ctx, addr, (uint32_t)nsubs);

            /* Fan out: write descriptor to each subscriber's shadow ring */
            for (int s = 0; s < nsubs; s++) {
                struct xsk_sub *sub = &ctx->subs[s];
                if (!__atomic_load_n(&sub->active, __ATOMIC_ACQUIRE)) {
                    frame_unref(ctx, addr);
                    continue;
                }
                if (!shadow_ring_push(sub->srx, addr, len)) {
                    /* Shadow ring full: drop this subscriber's copy */
                    fprintf(stderr,
                            "afxdp: shadow ring full for sub %u, dropping\n",
                            sub->container_ifindex);
                    if (frame_unref(ctx, addr) == 0)
                        recycle_queue[recycle_tail++ % UMEM_NUM_FRAMES] = addr;
                }
            }
        }

        pthread_mutex_unlock(&ctx->subs_lock);

        /* Check for frames ready to recycle (refcount == 0 from subs) */
        {
            uint32_t cq_idx;
            uint32_t comp = xsk_ring_cons__peek(&ctx->cq, 32, &cq_idx);
            for (uint32_t c = 0; c < comp; c++) {
                uint64_t addr = *xsk_ring_cons__comp_addr(&ctx->cq, cq_idx + c);
                if (frame_unref(ctx, addr) == 0)
                    recycle_queue[recycle_tail++ % UMEM_NUM_FRAMES] = addr;
            }
            xsk_ring_cons__release(&ctx->cq, comp);
        }

        /* Recycle ready frames to fill queue */
        int pending = (recycle_tail - recycle_head);
        if (pending > 0) {
            uint32_t fq_idx;
            uint32_t avail = xsk_ring_prod__reserve(&ctx->fq,
                                                    (uint32_t)pending,
                                                    &fq_idx);
            for (uint32_t r = 0; r < avail; r++) {
                *xsk_ring_prod__fill_addr(&ctx->fq, fq_idx + r) =
                    recycle_queue[recycle_head++ % UMEM_NUM_FRAMES];
            }
            xsk_ring_prod__submit(&ctx->fq, avail);
        }

        xsk_ring_cons__release(&ctx->agg_rx, rcvd);
    }

    return NULL;
}

/*
 * Called by subscriber code (container-side shim or test harness) when it
 * has finished reading a frame.  Decrements refcount; when it reaches 0
 * the frame is returned to the fill ring by the dispatch loop on its next
 * recycle pass.
 *
 * In a full implementation this would use a per-subscriber completion queue
 * that the dispatch loop drains.  For simplicity we expose the direct call
 * so callers can implement whatever protocol they prefer.
 */
void afxdp_frame_release(struct afxdp_ctx *ctx, uint64_t addr)
{
    /* refcount reaching 0 is noticed by dispatch loop via completion queue */
    (void)frame_unref(ctx, addr);
}
