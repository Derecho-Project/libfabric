#include <arpa/inet.h>
#include <linux/mman.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>

#include <ofi.h>

#define MR_SIZE 1073741824 // This will become a parameter of the test

#define LF_VERSION         OFI_VERSION_LATEST
#define MAX_LF_ADDR_SIZE   128 - sizeof(uint32_t) - 2 * sizeof(uint64_t)
#define CONF_RDMA_TX_DEPTH 256
#define CONF_RDMA_RX_DEPTH 256
#define MAX_PAYLOAD_SIZE   1472

// This can be moved once we relax the requirements on the DPDK MR alignment and size
#define ALIGN_TO(i, p)                                                                             \
    (__typeof__((                                                                                  \
        (i) + ((__typeof__(i))(p)-1))))((((i) + ((__typeof__(i))(p)-1))) &                         \
                                        (~((__typeof__(((i) + ((__typeof__(i))(p)-1))))((p)-1))))

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
    struct fid_cq     *rx_cq;                      /** completion queue for all rx rma operations */
    struct fid_cq     *tx_cq;                      /** completion queue for all tx rma operations */
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

static void *alloc_mem(size_t memsz, bool huge) {
    void *addr;
    int   flags;

    /* allocate anonymous pages */
    flags = MAP_ANONYMOUS | MAP_PRIVATE;
    if (huge) {
        // 2MB pages
        flags |= MAP_HUGETLB;
    }
    addr = mmap(NULL, memsz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (addr == MAP_FAILED) {
        return NULL;
    }
    return addr;
}

static struct addrinfo *parse_ip_port_string(const char *ip_port_str) {
    struct addrinfo  hints;
    struct addrinfo *res;
    char            *node      = NULL;
    char            *service   = NULL;
    uint32_t         colon_pos = 0;
    while (colon_pos < strlen(ip_port_str)) {
        if (ip_port_str[colon_pos] == ':') {
            break;
        }
        colon_pos++;
    }
    node = strndup(ip_port_str, colon_pos);
    /** if we do have the port **/
    if ((colon_pos + 1) < strlen(ip_port_str)) {
        service = strdup(ip_port_str + colon_pos + 1);
    }
    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_INET;

    int errcode = getaddrinfo(node, service, &hints, &res);
    if (errcode) {
        fprintf(stderr, "failed to get source address for %s. Error:%s\n", ip_port_str,
                gai_strerror(errcode));
    }
    if (service) {
        free(service);
    }
    if (node) {
        free(node);
    }
    return res;
}

static void default_context(const char *provider_name, const char *domain_name) {
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
    ;
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

    /** set the address space **/
    g_ctxt.hints->addr_format = FI_SOCKADDR_IN;
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

    /* Create a RX completion queue */
    g_ctxt.cq_attr.size = 2097152;
    ret                 = fi_cq_open(g_ctxt.domain, &(g_ctxt.cq_attr), &(g_ctxt.rx_cq), NULL);
    if (ret) {
        printf("fi_cq_open(1) failed: %s\n", fi_strerror(-ret));
        return ret;
    }
    if (!g_ctxt.rx_cq) {
        printf("Pointer to completion queue is null\n");
        return -1;
    }

    /* Create a TX completion queue */
    ret = fi_cq_open(g_ctxt.domain, &(g_ctxt.cq_attr), &(g_ctxt.tx_cq), NULL);
    if (ret) {
        printf("fi_cq_open(2) failed: %s\n", fi_strerror(-ret));
        return ret;
    }
    if (!g_ctxt.tx_cq) {
        printf("Pointer to completion queue is null\n");
        return -1;
    }

    /* Bind endpoint to event queue and completion queues */
    ret = fi_ep_bind(*ep, &(*eq)->fid, 0);
    if (ret) {
        printf("fi_ep_bind() failed to bind event queue: %s\n", fi_strerror(-ret));
        return ret;
    }

    uint64_t ep_flags = FI_RECV;
    ret               = fi_ep_bind(*ep, &(g_ctxt.rx_cq)->fid, ep_flags);
    if (ret) {
        printf("fi_ep_bind() failed to bind RX completion queue: %s\n", fi_strerror(-ret));
        return ret;
    }

    ep_flags = FI_TRANSMIT;
    ret      = fi_ep_bind(*ep, &(g_ctxt.tx_cq)->fid, ep_flags);
    if (ret) {
        printf("fi_ep_bind() failed to bind TX completion queue: %s\n", fi_strerror(-ret));
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
    size_t page_size = sysconf(_SC_PAGESIZE);
    g_mr.size        = ALIGN_TO(MR_SIZE, page_size);
    g_mr.buffer      = alloc_mem(g_mr.size, (page_size > sysconf(_SC_PAGESIZE)));

    if (!g_mr.buffer || g_mr.size <= 0) {
        printf("Failed to allocate a memory region of size %lu\n", g_mr.size);
        return -1;
    }
    const int mr_access = FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    bzero((void *)g_mr.buffer, g_mr.size);

    /* Register the memory */
    ret = fi_mr_reg(g_ctxt.domain, (void *)g_mr.buffer, g_mr.size, mr_access, 0, 0, 0, &g_mr.mr,
                    &page_size);
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

    // // Get the local address
    // ret = fi_getname(&(g_ctxt.pep->fid), g_ctxt.pep_addr, &(g_ctxt.pep_addr_len));
    // if (ret) {
    //     printf("fi_getname() failed: %s\n", fi_strerror(-ret));
    //     exit(2);
    // }
    // if (g_ctxt.pep_addr_len > MAX_LF_ADDR_SIZE) {
    //     printf("local name is too big to fit in local buffer\n");
    //     exit(2);
    // }

    // Synchronously read from the passive event queue, init the server ep
    struct fi_eq_cm_entry entry;
    uint32_t              event;
    ssize_t               n_read;
    struct fid_ep        *ep;
    struct fid_eq        *eq;

    n_read = fi_eq_sread(g_ctxt.peq, &event, &entry, sizeof(entry), -1, 0);
    if (n_read != sizeof(entry)) {
        fprintf(stderr, "Failed to get connection from remote. n_read=%ld\n", n_read);
        return;
    }
    if (event != FI_CONNREQ) {
        fprintf(stderr, "fi_eq_sread got unexpected event: %u, quitting...\n", event);
        return;
    }

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

    // Synchronously read from the eq of the new endpoint
    n_read = fi_eq_sread(eq, &event, &entry, sizeof(entry), -1, 0);
    if (n_read != sizeof(entry)) {
        printf("failed to connect remote. n_read=%ld.\n", n_read);
        return;
    }
    if (event != FI_CONNECTED) {
        fi_freeinfo(entry.info);
        printf("Unexpected CM event: %d.\n", event);
        return;
    }
    if (entry.fid != &(ep->fid)) {
        fi_freeinfo(entry.info);
        printf("Event fid@%p does not match accepting endpoint fid@%p.\n", entry.fid, &ep->fid);
        return;
    }
    fi_freeinfo(entry.info);
    printf("Server connected!\n");

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
            ret = fi_cq_readfrom(g_ctxt.rx_cq, &comp, 1, &src_addr);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("CQ read failed: %s", fi_strerror(-ret));
                break;
            }
        } while (ret == -FI_EAGAIN);

        printf("Received a new message [size = %lu]: ", comp.len);

        // Integrity check
        uint8_t content_ok = 1;
        for (int i = 0; i < comp.len; i++) {
            char c = ((char *)g_mr.buffer)[i];
            if (c != 'a') {
                content_ok = 0;
                printf("[ERROR] Wrong byte at index %d\n", i);
                break;
            }
        }
        if (content_ok) {
            printf("Content OK\n");
        }
    }

    fi_close(&ep->fid);
    fi_close(&eq->fid);

    printf("Server exiting...\n");
    return;
}

void do_client(const char *server_ip_and_port) {
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

    struct addrinfo *svr_ai = parse_ip_port_string(server_ip_and_port);
    if (!svr_ai) {
        fprintf(stderr, "%s cannot get server address from string:%s.\n", __func__,
                server_ip_and_port);
        return;
    }

    printf("Sleeping 3 seconds before connecting...\n");
    sleep(3);

    ret = fi_connect(ep, svr_ai->ai_addr, NULL, 0);
    if (ret) {
        printf("fi_connect() failed: %s\n", fi_strerror(-ret));
        freeaddrinfo(svr_ai);
        exit(2);
    }
    freeaddrinfo(svr_ai);

    // Get connection acceptance from the server
    ssize_t n_read = fi_eq_sread(eq, &event, &entry, sizeof(entry), -1, 0);
    if (n_read != sizeof(entry)) {
        fprintf(stderr, "failed to connect remote. n_read=%ld.\n", n_read);
        return;
    }
    if (event != FI_CONNECTED || entry.fid != &ep->fid) {
        fprintf(stderr, "fi_eq_sread() got unexpected even: %d, quitting...\n", event);
        return;
    }
    printf("Client connected!\n");
    // fflush(stdin);
    // sleep(10);

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
    char input[32];
    printf("Insert a message size: ");
    while (fgets((char *restrict)&input, 32, stdin) != NULL) {
        msg_iov.iov_len = atol(input);
        if (msg_iov.iov_len > g_mr.size) {
            printf("Size too big. Max is %ld, inserted size is %lu\n", g_mr.size, msg_iov.iov_len);
            printf("Insert a message size: ");
            continue;
        }
        if (msg_iov.iov_len <= 0) {
            printf("Size too small. Min is 1, inserted size is %lu\n", msg_iov.iov_len);
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

        // Get send completion.
        // TODO-1: Check what exactly we are receiving!
        // TODO-2: Are we sure we should wait until the ACK? This is the way uRDMA implemented this,
        // but not sure this is the same semantic of libfabric. Check the Libfabric spec.
        struct fi_cq_msg_entry comp;
        fi_addr_t              src_addr;
        do {
            ret = fi_cq_readfrom(g_ctxt.tx_cq, &comp, 1, &src_addr);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("CQ read failed: %s", fi_strerror(-ret));
                break;
            }
        } while (ret == -FI_EAGAIN);
        // TODO: Actually, we should check the completion state to know if the operation
        // was in fact successful or there was some error. Probably there is a LF-specific
        // way to do that
        printf("Message successfully sent!\n");

        printf("Insert a message size: ");
    }

    fi_shutdown(ep, 0);

    fi_close(&ep->fid);
    fi_close(&eq->fid);

    printf("Client disconnected, exiting...\n");
    return;
}

#define CMD_ARG_HELP                                                                               \
    "<info|client|server> <prov> <domain> "                                                        \
    "[remote_ip:remote_cm_port, mandatory client option]"

int main(int argc, char **argv) {
    int ret;
    if (argc < 3) {
        printf("Usage: %s" CMD_ARG_HELP "\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "client") == 0 && argc < 4) {
        printf("Usage: %s" CMD_ARG_HELP "\n", argv[0]);
        return 1;
    }

    // Initialize the Libfabric hints to ask for the right provider, fabric, domain.
    default_context(argv[2], argv[3]);

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
        do_client(argv[4]);
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
