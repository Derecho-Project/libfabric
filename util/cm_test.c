#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>

// This is not really necessary, but I need a quick way to get the log2 of a number
// so I'll use this.
#include <rte_common.h>

#include <ofi.h>

#define MR_SIZE       1073741824     // This will become a parameter of the test

#define LF_VERSION         OFI_VERSION_LATEST
#define MAX_LF_ADDR_SIZE   128 - sizeof(uint32_t) - 2 * sizeof(uint64_t)
#define CONF_RDMA_TX_DEPTH 256
#define CONF_RDMA_RX_DEPTH 256
#define MAX_PAYLOAD_SIZE   1472

#ifndef MAP_HUGE_SHIFT
/* older kernels (or FreeBSD) will not have this define */
#define HUGE_SHIFT (26)
#else
#define HUGE_SHIFT MAP_HUGE_SHIFT
#endif

#ifndef MAP_HUGETLB
/* FreeBSD may not have MAP_HUGETLB (in fact, it probably doesn't) */
#define HUGE_FLAG (0x40000)
#else
#define HUGE_FLAG MAP_HUGETLB
#endif

/**
 * Global states
 */
struct lf_ctxt {
    struct fi_info    *hints;                      /** hints */
    struct fi_info    *fi;                         /** fabric information */
    struct fid_fabric *fabric;                     /** fabric handle */
    struct fid_domain *domain;                     /** domain handle */
    struct fid_pep    *pep;                        /** passive endpoint for receiving connection */
    struct fid_eq     *peq;                        /** event queue for connection management */
    struct fid_cq     *cq;                         /** completion queue for all rma operations */
    size_t             pep_addr_len;               /** length of local pep address */
    char               pep_addr[MAX_LF_ADDR_SIZE]; /** local pep address */
    struct fi_eq_attr  eq_attr;                    /** event queue attributes */
    struct fi_cq_attr  cq_attr;                    /** completion queue attributes */
};

struct lf_mr {
    struct fid_mr *mr;     /** memory region */
    void          *buffer; /** buffer */
    size_t         size;   /** length of buffer */
};

/** The global context for libfabric */
struct lf_ctxt g_ctxt;
struct lf_mr   g_mr;

static int pagesz_flags(uint64_t page_sz) {
    /* as per mmap() manpage, all page sizes are log2 of page size
     * shifted by MAP_HUGE_SHIFT
     */
    int log2 = rte_log2_u64(page_sz);

    return (log2 << HUGE_SHIFT);
}

static void *alloc_mem(size_t memsz, size_t pgsz, bool huge) {
    void *addr;
    int   flags;

    /* allocate anonymous hugepages */
    flags = MAP_ANONYMOUS | MAP_PRIVATE;
    if (huge) {
        flags |= HUGE_FLAG | pagesz_flags(pgsz);
    }
    addr = mmap(NULL, memsz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (addr == MAP_FAILED) {
        return NULL;
    }
    return addr;
}

static void default_context(const char* provider_name, const char* domain_name) {
    memset((void *)&g_ctxt, 0, sizeof(struct lf_ctxt));

    /** Create a new empty fi_info structure */
    g_ctxt.hints = fi_allocinfo();
    if (g_ctxt.hints == NULL) {
        printf("fi_allocinfo failed.\n");
        exit(1);
    }
    /** Set the interface capabilities, see fi_getinfo(3) for details */
    g_ctxt.hints->caps = FI_MSG | FI_RMA | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    /** Use message API */
    g_ctxt.hints->ep_attr->type = FI_EP_MSG;
    /** Enable all modes */
    g_ctxt.hints->mode = ~0;
    /** Set the completion format to contain additional context */
    g_ctxt.cq_attr.format = FI_CQ_FORMAT_DATA;
    /** Use a file descriptor as the wait object (see polling_loop)*/
    g_ctxt.cq_attr.wait_obj = FI_WAIT_FD;
    /** Use a file descriptor as the wait object (see polling_loop)*/
    g_ctxt.eq_attr.wait_obj = FI_WAIT_FD;
    /** Set the size of the local pep address */
    g_ctxt.pep_addr_len = MAX_LF_ADDR_SIZE;

    /** Set the provider, can be verbs|psm|sockets|usnic */
    g_ctxt.hints->fabric_attr->prov_name = strdup(provider_name);
    /** Set the domain */
    g_ctxt.hints->domain_attr->name = strdup(domain_name);

    /** Set the memory region mode mode bits, see fi_mr(3) for details */
    if ((strcmp(g_ctxt.hints->fabric_attr->prov_name, "sockets") == 0) ||
        (strcmp(g_ctxt.hints->fabric_attr->prov_name, "tcp") == 0))
    {
        g_ctxt.hints->domain_attr->mr_mode = FI_MR_BASIC;
    } else { // default
        /** Set the sizes of the tx and rx queues */
        g_ctxt.hints->tx_attr->size = CONF_RDMA_TX_DEPTH;
        g_ctxt.hints->rx_attr->size = CONF_RDMA_RX_DEPTH;
        if (g_ctxt.hints->tx_attr->size == 0 || g_ctxt.hints->rx_attr->size == 0) {
            printf("Configuration error! RDMA TX and RX depth must be nonzero.\n");
            printf("Configuration error! RDMA TX and RX depth must be nonzero.\n");
            exit(1);
        }
        g_ctxt.hints->domain_attr->mr_mode =
            FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;
    }
}

int lf_initialize() {
    int ret;

    /* Initialize the fabric and domain */
    ret = fi_fabric(g_ctxt.fi->fabric_attr, &(g_ctxt.fabric), NULL);

    if (ret) {
        printf("fi_fabric() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    /** Initialize the event queue, initialize and configure pep  */
    // This must be done before the fi_domain() call!
    ret = fi_eq_open(g_ctxt.fabric, &(g_ctxt.eq_attr), &(g_ctxt.peq), NULL);
    if (ret) {
        printf("fi_eq_open() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    ret = fi_domain(g_ctxt.fabric, g_ctxt.fi, &(g_ctxt.domain), NULL);
    if (ret) {
        printf("fi_domain() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    return 0;
}

int init_active_ep(struct fi_info *fi, struct fid_ep **ep, struct fid_eq **eq) {
    int ret;

    /* Open an endpoint */
    ret = fi_endpoint(g_ctxt.domain, fi, ep, NULL);
    if (ret) {
        printf("fi_endpoint() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    /* Create an event queue */
    ret = fi_eq_open(g_ctxt.fabric, &(g_ctxt.eq_attr), eq, NULL);
    if (ret) {
        printf("fi_eq_open() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    /* Create a completion queue */
    g_ctxt.cq_attr.size = 2097152;
    ret                 = fi_cq_open(g_ctxt.domain, &(g_ctxt.cq_attr), &(g_ctxt.cq), NULL);
    if (ret) {
        printf("fi_cq_open() failed: %s\n", fi_strerror(-ret));
        return ret;
    }
    if (!g_ctxt.cq) {
        printf("Pointer to completion queue is null\n");
        return -1;
    }

    /* Bind endpoint to event queue and completion queue */
    ret = fi_ep_bind(*ep, &(*eq)->fid, 0);
    if (ret) {
        printf("fi_ep_bind() failed to bind event queue: %s\n", fi_strerror(-ret));
        return ret;
    }

    const uint64_t ep_flags = FI_RECV | FI_TRANSMIT | FI_SELECTIVE_COMPLETION;
    ret                     = fi_ep_bind(*ep, &(g_ctxt.cq)->fid, ep_flags);
    if (ret) {
        printf("fi_ep_bind() failed to bind completion queue: %s\n", fi_strerror(-ret));
        return ret;
    }

    ret = fi_enable(*ep);
    if (ret) {
        printf("fi_enable() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    return 0;
}

int register_memory_region() {
    int ret;

    // Important: memory allocation should be page aligned to the page size used by the DPDK
    // provider. The length must be a multiple of the page size.
    g_mr.size   = RTE_ALIGN(MR_SIZE, sysconf(_SC_PAGESIZE));
    g_mr.buffer = alloc_mem(g_mr.size, sysconf(_SC_PAGESIZE), false);

    if (!g_mr.buffer || g_mr.size <= 0) {
        printf("Failed to allocate a memory region of size %lu\n", g_mr.size);
        return -1;
    }
    const int mr_access = FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    bzero((void *)g_mr.buffer, g_mr.size);

    /* Register the memory */
    ret = fi_mr_reg(g_ctxt.domain, (void *)g_mr.buffer, g_mr.size, mr_access, 0, 0, 0, &g_mr.mr,
                    NULL);
    if (ret) {
        printf("fi_mr_reg() failed: %s\n", fi_strerror(-ret));
        return ret;
    }
    if (!g_mr.mr) {
        printf("Pointer to memory region is null\n");
        return -1;
    }

    return 0;
}

void do_server() {
    int ret;

    // Create passive EP (=> similar to server socket)
    ret = fi_passive_ep(g_ctxt.fabric, g_ctxt.fi, &(g_ctxt.pep), NULL);
    if (ret) {
        printf("fi_passive_ep() failed: %s\n", fi_strerror(-ret));
        exit(2);
    }
    // Bind the passive endpoint to the event queue
    ret = fi_pep_bind(g_ctxt.pep, &(g_ctxt.peq->fid), 0);
    if (ret) {
        printf("fi_pep_bind() failed: %s\n", fi_strerror(-ret));
        exit(2);
    }
    // Listen for incoming connections
    ret = fi_listen(g_ctxt.pep);
    if (ret) {
        printf("fi_listen() failed: %s\n", fi_strerror(-ret));
        exit(2);
    }
    // Get the local address
    ret = fi_getname(&(g_ctxt.pep->fid), g_ctxt.pep_addr, &(g_ctxt.pep_addr_len));
    if (ret) {
        printf("fi_getname() failed: %s\n", fi_strerror(-ret));
        exit(2);
    }
    if (g_ctxt.pep_addr_len > MAX_LF_ADDR_SIZE) {
        printf("local name is too big to fit in local buffer\n");
        exit(2);
    }

    // Synchronously read from the passive event queue, init the server ep
    struct fi_eq_cm_entry entry;
    uint32_t              event;
    ssize_t               n_read;
    struct fid_ep        *ep;
    struct fid_eq        *eq;

    // TODO: We should get an async event from the eq, but we don't have one yet!
    // n_read = fi_eq_sread(g_ctxt.peq, &event, &entry, sizeof(entry), -1, 0);
    // if (n_read != sizeof(entry)) {
    //     printf("Failed to get connection from remote. n_read=%ld\n", n_read);
    //     exit(2);
    // }

    // Instead, we simulate the async event by hand-crafting the entry
    entry.fid  = &(g_ctxt.pep->fid);
    entry.info = fi_dupinfo(g_ctxt.fi);

    // Create active ep and associate it to serve the incoming connection
    if (init_active_ep(entry.info, &ep, &eq)) {
        fi_reject(g_ctxt.pep, entry.info->handle, NULL, 0);
        fi_freeinfo(entry.info);
        printf("Failed to initialize server endpoint.\n");
        exit(2);
    }

    // Accept the incoming connection
    if (fi_accept(ep, NULL, 0)) {
        fi_reject(g_ctxt.pep, entry.info->handle, NULL, 0);
        fi_freeinfo(entry.info);
        printf("Failed to accept connection.\n");
        exit(2);
    }

    // TODO: We should get an async event from the eq, but we don't have one yet!
    // // Synchronously read from the eq of the new endpoint
    // n_read = fi_eq_sread(eq, &event, &entry, sizeof(entry), -1, 0);
    // if (n_read != sizeof(entry)) {
    //     printf("failed to connect remote. n_read=%ld.\n", n_read);
    //     exit(2);
    // }
    // if (event != FI_CONNECTED || entry.fid != &(ep->fid)) {
    //     fi_freeinfo(entry.info);
    //     printf("Unexpected CM event: %d.\n", event);
    //     exit(2);
    // }
    // fi_freeinfo(entry.info);

    // Server loop
    struct iovec  msg_iov;
    struct fi_msg msg;
    msg_iov.iov_base = g_mr.buffer;
    msg_iov.iov_len  = g_mr.size;

    while (1) {
        bzero((void *)g_mr.buffer, g_mr.size);
        msg.msg_iov = &msg_iov;

        void *desc    = fi_mr_desc(g_mr.mr);
        msg.desc      = &desc;
        msg.iov_count = 1;
        msg.addr      = 0;
        msg.context   = NULL;

        // Post a receive request
        ret = fi_recvmsg(ep, &msg, 0);
        if (ret == -FI_EAGAIN) {
            usleep(100);
            continue;
        } else if (ret) {
            printf("fi_recvmsg() failed: %s\n", fi_strerror(-ret));
            exit(2);
        }

        // Get the associated completion
        struct fi_cq_msg_entry comp;
        fi_addr_t              src_addr;
        do {
            ret = fi_cq_readfrom(g_ctxt.cq, &comp, 1, &src_addr);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("CQ read failed: %s", fi_strerror(-ret));
                break;
            }
        } while (ret == -FI_EAGAIN);

        printf("Received a new message [size = %u]: %s\n", comp.len, (char *)g_mr.buffer);
    }
}

void do_client() {
    int ret;

    // Active endpoint and associated event queue
    struct fid_ep *ep;
    struct fid_eq *eq;

    if (init_active_ep(g_ctxt.fi, &ep, &eq)) {
        printf("failed to initialize client endpoint.\n");
        exit(2);
    }

    // Connect to the server
    struct fi_eq_cm_entry entry;
    uint32_t              event;

    ret = fi_connect(ep, g_ctxt.pep_addr, NULL, 0);
    if (ret) {
        printf("fi_connect() failed: %s\n", fi_strerror(-ret));
        exit(2);
    }

    // TODO: We should get an async event from the eq, but we don't have one yet!
    // Get connection acceptance from the server
    // ssize_t n_read = fi_eq_sread(eq, &event, &entry, sizeof(entry), -1, 0);
    // if (n_read != sizeof(entry)) {
    //     printf("failed to connect remote. n_read=%ld.\n", n_read);
    //     exit(2);
    // }
    // if (event != FI_CONNECTED || entry.fid != &ep->fid) {
    //     printf("RDMC Unexpected CM event: %d.\n", event);
    //     exit(2);
    // }

    // Now the connection is open, I can send
    struct iovec  msg_iov;
    struct fi_msg msg;

    msg_iov.iov_base = g_mr.buffer;
    void *desc       = fi_mr_desc(g_mr.mr);
    msg.desc         = &desc;
    msg.iov_count    = 1;
    msg.addr         = 0;
    msg.context      = NULL;
    msg.data         = 0;
    msg.msg_iov      = &msg_iov;

    // Send message
    char input[8];
    printf("Insert a message size: ");
    while (fgets((char *restrict)&input, 8, stdin) != NULL) {
        msg_iov.iov_len = atol(input);
        if (msg_iov.iov_len > g_mr.size) {
            printf("Size too big. Max is %d, inserted size is %ld\n", g_mr.size, msg_iov.iov_len);
            printf("Insert a message size: ");
            continue;
        }

        // Fill the buffer with random content
        memset(g_mr.buffer, 'a', msg_iov.iov_len);

        // Post a send request
        ret = fi_sendmsg(ep, &msg, FI_COMPLETION);
        if (ret) {
            printf("fi_sendmsg() failed: %s\n", fi_strerror(-ret));
            printf("Insert a message size: ");
            continue;
        }

        // TODO: Get send completion. For the moment, just sleep
        usleep(1000);

        printf("Insert a message size: ");
    }
}



int main(int argc, char **argv) {
    int ret;
    if (argc < 4) {
        printf("Usage: %s <info|client|server> <prov> <domain>\n", argv[0]);
        exit(1);
    }

    // Initialize the Libfabric hints to ask for the right provider, fabric, domain.
    default_context(argv[2],argv[3]);

    // Get the fabric info
    ret = fi_getinfo(LF_VERSION, NULL, NULL, 0, g_ctxt.hints, &g_ctxt.fi);
    if (ret != 0) {
        printf("%s:%s fi_getinfo failed: %s\n", __FILE__, __func__, fi_strerror(-ret));
        exit(1);
    }

    if (strcmp(argv[1], "info") == 0) {
        // Print all the endpoints found with the filter "hints"
        struct fi_info *info = g_ctxt.fi;
        while (info != NULL) {
            printf("provider: %s\n", info->fabric_attr->prov_name);
            printf("domain: %s\n", info->domain_attr->name);
            printf("fabric: %s\n", info->fabric_attr->name);
            printf("\n");
            info = info->next;
        }

        goto cleanup_and_exit;
    }

    // Create the fabric, domain, cq, and configure pep
    ret = lf_initialize();
    if (ret != 0) {
        printf("lf_initialize failed: %s\n", fi_strerror(-ret));
        exit(1);
    }

    // Allocate a memory region
    ret = register_memory_region();
    if (ret != 0) {
        printf("register_memory_region failed: %s\n", fi_strerror(-ret));
        exit(1);
    }

    if (strcmp(argv[1], "client") == 0) {

        printf("Starting Client... \n");
        do_client();
    } else if (strcmp(argv[1], "server") == 0) {

        printf("Starting Server...\n");
        do_server();
    } else {
        printf("Usage: %s <info|client|server>\n", argv[0]);
        exit(1);
    }

cleanup_and_exit:
    free(g_mr.buffer);
    fi_freeinfo(g_ctxt.fi);
    return 0;
}
