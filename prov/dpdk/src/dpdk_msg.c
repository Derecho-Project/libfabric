#include "fi_dpdk.h"

////// OPS
static ssize_t dpdk_recv(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
                         fi_addr_t src_addr, void *context) {

    // Here I should access the RX queue of the endpoint
    // and see if there are events I can deliver
    printf("[dpdk_recv] UNIMPLEMENTED\n");
    return 0;
}

static ssize_t dpdk_recvv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc, size_t count,
                          fi_addr_t src_addr, void *context) {
    // Here I should access the RX queue of the endpoint
    // and see if there are events I can deliver
    printf("[dpdk_recv] UNIMPLEMENTED\n");
    return 0;
}

static ssize_t dpdk_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags) {
    // Here I should access the RX queue of the endpoint
    // and see if there are events I can deliver
    printf("[dpdk_recv] UNIMPLEMENTED\n");
    return 0;
}

static ssize_t dpdk_send(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
                         fi_addr_t dest_addr, void *context) {

    // Here I should access the TX queue of the endpoint
    // insert the message and return
    printf("[dpdk_send] UNIMPLEMENTED\n");
    return len;
}

static ssize_t dpdk_sendv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc, size_t count,
                          fi_addr_t dest_addr, void *context) {
    printf("[dpdk_sendv] UNIMPLEMENTED\n");
    return iov->iov_len;
}

static ssize_t dpdk_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags) {
    printf("[dpdk_sendmsg] UNIMPLEMENTED\n");
    fflush(stdout);
    return 0;
}

static ssize_t dpdk_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
                           fi_addr_t dest_addr) {
    printf("[dpdk_inject] UNIMPLEMENTED\n");
    return len;
}

static ssize_t dpdk_senddata(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
                             uint64_t data, fi_addr_t dest_addr, void *context) {
    printf("[dpdk_senddata] UNIMPLEMENTED\n");
    return len;
}

static ssize_t dpdk_injectdata(struct fid_ep *ep_fid, const void *buf, size_t len, uint64_t data,
                               fi_addr_t dest_addr) {
    printf("[dpdk_injectdata] UNIMPLEMENTED\n");
    return len;
}

struct fi_ops_msg dpdk_msg_ops = {
    .size       = sizeof(struct fi_ops_msg),
    .recv       = dpdk_recv,
    .recvv      = dpdk_recvv,
    .recvmsg    = dpdk_recvmsg,
    .send       = dpdk_send,
    .sendv      = dpdk_sendv,
    .sendmsg    = dpdk_sendmsg,
    .inject     = dpdk_inject,
    .senddata   = dpdk_senddata,
    .injectdata = dpdk_injectdata,
};