#include "fi_dpdk.h"

/* This file implements the MR management for the libfabric DPDK provider.
 * IMPORTANT: The memory registered with this provider must be both:
 * 1) Page aligned, to a page size that in the future will be configurable, and currently is the
 * default system page size (sysconf(_SC_PAGESIZE))
 * 2) The length of the buffer to register must be a multiple of that page size.
 * In Libfabric, the MRs are associated to the domain.
 */

// ===== Related FUNCTIONS =====
struct dpdk_mr *dpdk_mr_lookup(struct dpdk_mr_table *tbl, uint32_t rkey) {
    struct dpdk_mr *candidate;

    for (candidate = tbl->entries[rkey % tbl->capacity]; candidate != NULL;
         candidate = candidate->next)
    {
        if (candidate->rkey == rkey) {
            return candidate;
        }
    }

    return NULL;
} /* usiw_mr_lookup */

// ===== fi_mr IMPLEMENTATION =====

/** Register a user-allocated memory area with DPDK. It can be of arbitrary size (*)
 * TODO: (*) Actually, we currently require that the page is aligned to the page size passed as
 * argument (or the default system size), and that its len is power of 2. We should relax this
 * requirement and transparently adjust the area to those requirements.
 * @param fid       The domain fid
 * @param buf       The pointer to the memory area to register
 * @param len       The length of the memory area to register
 * @param access    The access flags for the Libfabric memory region registration
 * @param offset    The offset for the Libfabric memory region
 * @param requested_key The key for the Libfabric memory region
 * @param flags     The flags for the Libfabric memory region registration
 * @param mr        The Libfabric memory region to register
 * @param context   If not NULL, we assume it represents the page size to use for the memory
 * registration. If NULL, we use the default system page size (sysconf(_SC_PAGESIZE))
 *
 * @return 0 on success, negative error code on failure
 */
static int dpdk_mr_reg(struct fid *fid, const void *buf, size_t len, uint64_t access,
                       uint64_t offset, uint64_t requested_key, uint64_t flags, struct fid_mr **mr,
                       void *context) {

    int ret;

    if (!buf) {
        FI_WARN(&dpdk_prov, FI_LOG_MR,
                "Memory Region to register is NULL. Application must allocate it");
        return -FI_EINVAL;
    }
    if (len == 0) {
        FI_WARN(&dpdk_prov, FI_LOG_MR, "Memory Region to register has length 0");
        return -FI_EINVAL;
    }

    // TODO: find a better way to generate the key
    uint64_t new_key = rand();

    /* Check that the requested key does not exist already */
    struct dpdk_domain *dpdk_domain =
        container_of(fid, struct dpdk_domain, util_domain.domain_fid.fid);

    struct dpdk_mr_table *mr_tbl = &dpdk_domain->mr_tbl;
    ofi_genlock_lock(&dpdk_domain->mr_tbl_lock);
    struct dpdk_mr *prev_mr = dpdk_mr_lookup(mr_tbl, new_key);
    while (prev_mr != NULL) {
        new_key++;
        prev_mr = dpdk_mr_lookup(mr_tbl, new_key);
    }
    ofi_genlock_unlock(&dpdk_domain->mr_tbl_lock);

    /* Libfabric-specific section */
    struct dpdk_mr *dpdk_mr = calloc(1, sizeof(struct dpdk_mr));
    if (!dpdk_mr) {
        return -FI_ENOMEM;
    }
    dpdk_mr->buf = buf;
    dpdk_mr->len = len;

    (*mr) = &dpdk_mr->mr_fid;
    ret   = ofi_mr_reg(fid, buf, len, access, offset, new_key, flags, mr, context);
    if (ret) {
        free(dpdk_mr);
        return ret;
    }

    /* DPDK-specific section */
    char  *data_buffer_orig = buf;
    size_t data_buffer_len  = len;
    size_t page_size        = context == NULL ? sysconf(_SC_PAGESIZE) : *((size_t *)context);

    // 1) Check if the area is ok for DPDK registration
    if (!rte_is_power_of_2(page_size) || !rte_is_aligned(data_buffer_orig, page_size)) {
        FI_WARN(&dpdk_prov, FI_LOG_MR, "%s():%i: Invalid page size or unaligned buffer: %p",
                data_buffer_orig, __func__, __LINE__);
        goto exit_errno;
    }

    // 2) Compute total number of pages needed and pin them
    uint32_t n_pages = data_buffer_len < page_size ? 1 : data_buffer_len / page_size;
    ret              = mlock(data_buffer_orig, data_buffer_len);
    if (ret < 0) {
        FI_WARN(&dpdk_prov, FI_LOG_MR, "%s():%i: Failed to pin memory: %s", __func__, __LINE__,
                strerror(errno));
        goto exit_errno;
    }

    // 3) Allocate and populate IOVA address vector
    rte_iova_t *iovas = NULL;
    iovas             = malloc(sizeof(*iovas) * n_pages);
    for (uint32_t cur_page = 0; cur_page < n_pages; cur_page++) {
        rte_iova_t iova;
        size_t     offset;
        void      *cur;
        offset = page_size * cur_page;
        cur    = RTE_PTR_ADD(data_buffer_orig, offset);
        /* touch the page before getting its IOVA */
        memset((void *)cur, 1, page_size);
        iova            = rte_mem_virt2iova(cur);
        iovas[cur_page] = iova;
    }
    if (iovas == NULL) {
        FI_WARN(&dpdk_prov, FI_LOG_MR, "%s():%i: Failed to compute iovas", __func__, __LINE__);
        return rte_errno;
    }

    // 4) Register external memory with DPDK and the device
    // TODO: This may violate the DPDK memory segment list limit. Check the documentation.
    ret = rte_extmem_register(data_buffer_orig, data_buffer_len, iovas, n_pages, page_size);
    if (ret < 0 && rte_errno != EEXIST) {
        FI_WARN(&dpdk_prov, FI_LOG_MR, "%s():%i: Failed to register external memory with DPDK: %s",
                __func__, __LINE__, rte_strerror(rte_errno));
        printf("Failed to register external memory with key with DPDK: %s\n",
               rte_strerror(rte_errno));
        goto exit_rte_errno;
    }

    // 5) Register pages for DMAs with the NIC associated with the domain
    struct rte_eth_dev_info dev_info;
    // [Lorenzo] EXPERIMENTAL: This is the port_id of the VF (Mellanox).
    rte_eth_dev_info_get(0, &dev_info);
    for (uint32_t cur_page = 0; cur_page < n_pages; cur_page++) {
        ret = rte_dev_dma_map(dev_info.device, data_buffer_orig + (cur_page * page_size),
                              iovas[cur_page], page_size);
        if (ret < 0) {
            FI_WARN(&dpdk_prov, FI_LOG_MR, "%s():%i: Failed to register memory for DMA: %s\n",
                    __func__, __LINE__, rte_strerror(rte_errno));
            goto exit_rte_errno;
        }
    }

    // 6) Free the iova vector and return
    free(iovas);

    // 7) Setup memory keys
    dpdk_mr->rkey   = new_key;
    dpdk_mr->lkey   = new_key;
    dpdk_mr->access = access;

    // 8) Add the MR to the MR table of the domain
    uint32_t hash = new_key % mr_tbl->capacity;
    ofi_genlock_lock(&dpdk_domain->mr_tbl_lock);
    dpdk_mr->next         = mr_tbl->entries[hash];
    mr_tbl->entries[hash] = dpdk_mr;
    mr_tbl->mr_count++;
    ofi_genlock_unlock(&dpdk_domain->mr_tbl_lock);

    FI_DBG(&dpdk_prov, FI_LOG_MR,
           "%s():%i: Registered memory region with key=%lu addr=[%p, %p] size=%lu\n", __func__,
           __LINE__, new_key, data_buffer_orig, data_buffer_orig + data_buffer_len,
           data_buffer_len);

    return FI_SUCCESS;

exit_errno:
    ofi_mr_close(fid);
    return errno;
exit_rte_errno:
    free(iovas);
    ofi_mr_close(fid);
    return rte_errno;
}

static int dpdk_mr_regv(struct fid *fid, const struct iovec *iov, size_t count, uint64_t access,
                        uint64_t offset, uint64_t requested_key, uint64_t flags, struct fid_mr **mr,
                        void *context) {
    // TODO: Unimplemented
    printf("[dpdk_mr_regv] UNIMPLEMENTED\n");
    return ofi_mr_regv(fid, iov, count, access, offset, requested_key, flags, mr, context);
}

static int dpdk_mr_regattr(struct fid *fid, const struct fi_mr_attr *attr, uint64_t flags,
                           struct fid_mr **mr) {
    // TODO: Unimplemented
    printf("[dpdk_mr_regattr] UNIMPLEMENTED\n");
    return ofi_mr_regattr(fid, attr, flags, mr);
}

// Assigned to domain->util_domain.domain_fid.fid.ops in dpdk_domain.c
struct fi_ops_mr dpdk_domain_fi_ops_mr = {
    .size    = sizeof(struct fi_ops_mr),
    .reg     = dpdk_mr_reg,
    .regv    = dpdk_mr_regv,
    .regattr = dpdk_mr_regattr,
};
