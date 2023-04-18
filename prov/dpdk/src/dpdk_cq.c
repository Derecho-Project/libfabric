#include "fi_dpdk.h"

//====================== Helper functions ======================
enum { SIZE_POW2_MAX = (INT_MAX >> 1) + 1 };

/** Returns the least power of 2 greater than in.  If in is greater than the
 * highest power of 2 representable as a size_t, then the behavior is
 * undefined. */
static int next_pow2(int in) {
    int out;
    assert(in < SIZE_POW2_MAX);
    for (out = 1; out < in; out <<= 1)
        ;
    return out;
} /* next_pow2 */

//====================== OPS ======================
static ssize_t dpdk_cq_readfrom(struct fid_cq *cq_fid, void *buf, size_t count,
                                fi_addr_t *src_addr) {
    int ret;

    // Get a dpdk_ep from the cq
    struct dpdk_cq *cq = container_of(cq_fid, struct dpdk_cq, util_cq.cq_fid);
    // struct dpdk_ep *ep = cq->ep;

    // Array of WQEs that I read from the CQE.
    // I am expected to return only those successfult?
    // See the libfabric spec for more details.
    struct fi_dpdk_wc *cqe[dpdk_default_rx_burst_size];

    // rte_spinlock_lock(&ep->rq.lock);
    ret = rte_ring_dequeue_burst(cq->cqe_ring, (void **)cqe, count, NULL);
    // rte_spinlock_unlock(&ep->rq.lock);
    if (ret == 0) {
        return -EAGAIN;
    }

    // TODO: WHat if I have more than one CQE TO RETURN?
    struct fi_cq_msg_entry *comp = (struct fi_cq_msg_entry *)buf;
    comp->flags                  = cqe[0]->wc_flags;
    comp->len                    = cqe[0]->byte_len;
    comp->op_context             = cqe[0]->wr_context;

    // TODO: implement according to the spec
    if (src_addr) {
        *src_addr = FI_ADDR_NOTAVAIL;
    }

    // Return the CQ descriptor to the free ring
    rte_ring_enqueue_burst(cq->free_ring, (void **)cqe, count, NULL);

    return ret;
}

static ssize_t dpdk_cq_readerr(struct fid_cq *cq_fid, struct fi_cq_err_entry *buf, uint64_t flags) {
    printf("[dpdk_cq_readerr] UNIMPLEMENTED\n");
    return 0;
}

static int dpdk_cq_close(struct fid *fid) {
    int             ret;
    struct dpdk_cq *cq;

    // TODO: finish this
    printf("[dpdk_cq_close] UNIMPLEMENTED\n");

    cq  = container_of(fid, struct dpdk_cq, util_cq.cq_fid.fid);
    ret = ofi_cq_cleanup(&cq->util_cq);
    if (ret)
        return ret;

    free(cq);
    return 0;
}

static int dpdk_cq_control(struct fid *fid, int command, void *arg) {
    struct util_cq *cq;
    int             ret;

    cq = container_of(fid, struct util_cq, cq_fid.fid);

    switch (command) {
    case FI_GETWAIT:
    case FI_GETWAITOBJ:
        if (!cq->wait)
            return -FI_ENODATA;

        ret = fi_control(&cq->wait->wait_fid.fid, command, arg);
        break;
    default:
        return -FI_ENOSYS;
    }

    return ret;
}

static struct fi_ops dpdk_cq_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_cq_close,
    .bind     = fi_no_bind,
    .control  = dpdk_cq_control,
    .ops_open = fi_no_ops_open,
};

static struct fi_ops_cq dpdk_cq_ops = {
    .size      = sizeof(struct fi_ops_cq),
    .read      = ofi_cq_read, // FW to readfrom
    .readfrom  = dpdk_cq_readfrom,
    .readerr   = dpdk_cq_readerr,
    .sread     = ofi_cq_sread,
    .sreadfrom = ofi_cq_sreadfrom,
    .signal    = ofi_cq_signal,
    .strerror  = ofi_cq_strerror,
};

static void dpdk_cq_progress_noop(struct util_cq *util_cq) {
    // Just like in the verbs provider, this should not be called.
    assert(0);
}

/*
static int dpdk_cq_wait_try_func(void *arg) {
    OFI_UNUSED(arg);
    return FI_SUCCESS;
}
*/

/* Create the CQ */
int dpdk_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr, struct fid_cq **cq_fid,
                 void *context) {
    struct dpdk_cq   *cq;
    struct fi_cq_attr cq_attr;
    int               ret;

    // 1. Libfabric-specific initialization
    cq = calloc(1, sizeof(*cq));
    if (!cq)
        return -FI_ENOMEM;

    if (!attr->size)
        attr->size = DPDK_DEF_CQ_SIZE;

    if (attr->wait_obj == FI_WAIT_UNSPEC) {
        cq_attr          = *attr;
        cq_attr.wait_obj = FI_WAIT_POLLFD;
        attr             = &cq_attr;
    }

    ret = ofi_cq_init(&dpdk_prov, domain, attr, &cq->util_cq, &dpdk_cq_progress_noop, context);
    if (ret) {
        goto free_cq;
    }

    *cq_fid            = &cq->util_cq.cq_fid;
    (*cq_fid)->fid.ops = &dpdk_cq_fi_ops;
    (*cq_fid)->ops     = &dpdk_cq_ops;

    // 2. DPDK-specific initialization
    // struct dpdk_domain *dpdk_domain =
    //     container_of(domain, struct dpdk_domain, util_domain.domain_fid);
    atomic_init(&cq->refcnt, 1);
    cq->cq_id = 0; // TODO: Assign a unique ID to the CQ
    // Number of entries (must be a power of 2 minus 1);
    cq->capacity = next_pow2(attr->size + 1) - 1;
    // Allocate the DPDK rings
    char name[RTE_RING_NAMESIZE];
    snprintf(name, RTE_RING_NAMESIZE, "cq%" PRIu32 "_ready_ring", cq->cq_id);
    cq->cqe_ring = rte_malloc(NULL, rte_ring_get_memsize(cq->capacity + 1), rte_socket_id());
    if (!cq->cqe_ring) {
        ret = rte_errno;
        goto cleanup;
    }
    // Ring is single consumer (the user thread?) and single producer (the loop thread?)
    ret = rte_ring_init(cq->cqe_ring, name, cq->capacity + 1, RING_F_SC_DEQ | RING_F_SP_ENQ);
    if (ret) {
        ret = -ret;
        rte_free(cq->cqe_ring);
        goto cleanup;
    }
    snprintf(name, RTE_RING_NAMESIZE, "cq%" PRIu32 "_empty_ring", cq->cq_id);
    cq->free_ring = rte_malloc(
        NULL, rte_ring_get_memsize(cq->capacity + 1),
        rte_socket_id()); // TODO: maybe we should retrieve it from the dpdk_domain struct
    if (!cq->cqe_ring) {
        ret = rte_errno;
        rte_free(cq->cqe_ring);
        goto cleanup;
    }
    ret = rte_ring_init(cq->free_ring, name, cq->capacity + 1, RING_F_SC_DEQ);
    if (!cq->free_ring) {
        errno = ret;
        rte_free(cq->free_ring);
        rte_free(cq->cqe_ring);
        goto cleanup;
    }
    // Allocate the storage space
    cq->storage = malloc(cq->capacity * sizeof(struct fi_dpdk_wc));
    for (int x = 0; x < cq->capacity; ++x) {
        rte_ring_enqueue(cq->free_ring, &cq->storage[x]);
    }
    cq->ep_count = 0;
    atomic_init(&cq->notify_flag, false);
    return 0;

cleanup:
    ofi_cq_cleanup(&cq->util_cq);
free_cq:
    free(cq);
    return ret;
}
