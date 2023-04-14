#include "fi_dpdk.h"

/* This file implements the MR management for the libfabric DPDK provider.
 * IMPORTANT: The memory registered with this provider must be both:
 * 1) Page aligned, to a page size that in the future will be configurable, and currently is the
 * default system page size (sysconf(_SC_PAGESIZE))
 * 2) The length of the buffer to register must be a multiple of that page size
 *
 * TODO: [Lorenzo] Currently, there seems to be an issue with memory registration when using a
 * non-Mellanox driver. The rte_dev_dma_map succeeds, but when I send chunks of data >4096 (the
 * default page size) the driver actually sends garbage on the network, which means the memory is
 * not actually registered. We need to FIX that.
 */

// ===== HELPER FUNCTIONS =====

// ===== fi_mr IMPLEMENTATION =====
static int dpdk_mr_reg(struct fid *fid, const void *buf, size_t len, uint64_t access,
                       uint64_t offset, uint64_t requested_key, uint64_t flags, struct fid_mr **mr,
                       void *context) {

    int ret;

    if (!buf) {
        FI_WARN(&dpdk_prov, FI_LOG_MR,
                "Memory Region to register is NULL. Application must allocate it");
        return -FI_EINVAL;
    }

    struct dpdk_domain *dpdk_domain =
        container_of(fid, struct dpdk_domain, util_domain.domain_fid.fid);

    struct dpdk_mr *dpdk_mr = calloc(1, sizeof(struct dpdk_mr));
    if (!dpdk_mr) {
        return -FI_ENOMEM;
    }
    dpdk_mr->buf = buf;
    dpdk_mr->len = len;

    (*mr) = &dpdk_mr->mr_fid;
    ret   = ofi_mr_reg(fid, buf, len, access, offset, requested_key, flags, mr, context);
    if (ret) {
        free(dpdk_mr);
        return ret;
    }

    char  *data_buffer_orig = buf;
    size_t data_buffer_len  = len;
    // TODO: understand how to handle this. We need a way to learn which kind of
    // page size the application want to use. If the application wants to use hugepages,
    // in this current implementation, it will have to do it automously and let us know
    // the page size it chose.
    size_t page_size = sysconf(_SC_PAGESIZE);

    rte_iova_t *iovas   = NULL;
    uint32_t    n_pages = data_buffer_len / page_size;
    iovas               = malloc(sizeof(*iovas) * n_pages);

    // a-1) Pin pages
    // TODO: With the INTEL driver, this seems to be conflicting with the rte_dev_dma_map() call
    // below. We need to understand if the mlock is necessary and if so how to solve that.
    mlock(data_buffer_orig, data_buffer_len);

    // a-2) Populate IOVA addresses
    for (uint32_t cur_page = 0; cur_page < n_pages; cur_page++) {
        rte_iova_t iova;
        size_t     offset;
        void      *cur;
        offset = page_size * cur_page;
        cur    = RTE_PTR_ADD(data_buffer_orig, offset);
        /* touch the page before getting its IOVA */
        bzero((void *)cur, page_size);
        iova            = rte_mem_virt2iova(cur);
        iovas[cur_page] = iova;
    }
    if (iovas == NULL) {
        FI_WARN(&dpdk_prov, FI_LOG_MR, "%s():%i: Failed to compute iovas", __func__, __LINE__);
        return rte_errno;
    }

    if (!rte_is_power_of_2(page_size) || !rte_is_aligned(data_buffer_orig, page_size)) {
        FI_WARN(&dpdk_prov, FI_LOG_MR, "%s():%i: Invalid page size or unaligned buffer", __func__,
                __LINE__);
        return -FI_EINVAL;
    }

    // b) Register external memory with DPDK and the device
    ret = rte_extmem_register(data_buffer_orig, data_buffer_len, iovas, n_pages, page_size);
    if (ret < 0) {
        // FI_WARN(&dpdk_prov, FI_LOG_MR,
        //         "%s():%i: Failed to register external memory with DPDK: %s", __func__,
        //         __LINE__, rte_strerror(rte_errno));
        // FI_WARN(
        //     &dpdk_prov, FI_LOG_MR,
        //     "Remember: page alignment is required for registered memory! Current page size is:
        //     %lu", page_size);
        printf("Failed to register external memory with DPDK: %s\n", rte_strerror(rte_errno));
        return rte_errno;
    }

    // c) Register pages for DMAs with the NIC associated with the domain
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(dpdk_domain->res->port_id, &dev_info);
    ret = rte_dev_dma_map(dev_info.device, data_buffer_orig, rte_mem_virt2iova(data_buffer_orig),
                          data_buffer_len);
    if (ret < 0) {
        printf("%s():%i: Failed to pin memory for DMA\n", __func__, __LINE__);
        return rte_errno;
    }

    // d) Free the iova vector
    free(iovas);

    return FI_SUCCESS;
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
