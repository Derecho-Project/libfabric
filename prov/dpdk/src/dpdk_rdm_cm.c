#include "fi_dpdk.h"

struct dpdk_rdm_cm {
    uint8_t  version;
    uint8_t  resv;
    uint16_t port;
    uint32_t pid;
};

static void dpdk_process_connreq(struct fi_eq_cm_entry *cm_entry) {
    printf("[dpdk_process_connreq] UNIMPLEMENTED!\n");
}

void dpdk_handle_event_list(struct dpdk_progress *progress) {
    struct dpdk_event  *event;
    struct slist_entry *item;
    struct dpdk_rdm_cm *msg;
    struct dpdk_conn   *conn;

    assert(ofi_genlock_held(&progress->rdm_lock));
    while (!slist_empty(&progress->event_list)) {
        item  = slist_remove_head(&progress->event_list);
        event = container_of(item, struct dpdk_event, list_entry);

        FI_INFO(&dpdk_prov, FI_LOG_EP_CTRL, "event %s\n",
                fi_tostr(&event->event, FI_TYPE_EQ_EVENT));

        switch (event->event) {
        case FI_CONNREQ:
            dpdk_process_connreq(&event->cm_entry);
            break;
        case FI_CONNECTED:
            conn             = event->cm_entry.fid->context;
            msg              = (struct dpdk_rdm_cm *)event->cm_entry.data;
            conn->remote_pid = ntohl(msg->pid);
            break;
        case FI_SHUTDOWN:
            conn = event->cm_entry.fid->context;
            // TODO: handle shutdown in a DPDK-SPECIFIC WAY
            //  dpdk_close_conn(conn);
            //  dpdk_free_conn(conn);
            break;
        default:
            assert(0);
            break;
        }
        free(event);
    };
}