#include "fi_dpdk.h"

// ================ Helper functions =================
static void dpdk_ep_progress(struct dpdk_ep *ep) {
    // TODO: IMPLEMENT
}

// ================ Progress functions =================
/* This function initializes the progress */
int dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info) {
    int ret;

    // TODO: this should become a parameter in some way
    progress->lcore_id      = 1;
    progress->stop_progress = 0;
    progress->fid.fclass    = DPDK_CLASS_PROGRESS;
    slist_init(&progress->event_list);

    // Mutex to access EP list
    ret = ofi_genlock_init(&progress->lock, OFI_LOCK_MUTEX);
    if (ret) {
        goto err;
    }

    ret = ofi_bufpool_create(&progress->xfer_pool, sizeof(struct dpdk_xfer_entry) + dpdk_max_inject,
                             16, 0, 1024, 0);
    if (ret) {
        goto err;
    }

    return 0;

err:
    ofi_bufpool_destroy(progress->xfer_pool);
    return ret;
}

int dpdk_start_progress(struct dpdk_progress *progress) {
    int ret;

    ret = rte_eal_remote_launch(dpdk_run_progress, progress, progress->lcore_id);
    if (ret) {
        FI_WARN(&dpdk_prov, FI_LOG_DOMAIN, "unable to start progress lcore thread\n");
        ret = -ret;
    }

    return ret;
}

// This is the main DPDK loop => one polling thread per device (= per domain)
void dpdk_run_progress(struct dpdk_progress *progress, bool clear_signal) {
    struct slist_entry *cur, *prev;
    struct dpdk_ep     *ep;

    while (!progress->stop_progress) {

        // For each endpoint, TX data

        // RX data, parse the packets, dispatch them to the right EP based on the transport-level
        // port
    }
}

void dpdk_close_progress(struct dpdk_progress *progress) {
    printf("dpdk_close_progress: UNIMPLEMENTED\n");
}