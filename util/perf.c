#include <arpa/inet.h>
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

// This is not really necessary, but I need a quick way to get the log2 of a number
// so I'll use this.
#include <rte_common.h>

#include <ofi.h>

#define MR_SIZE 1073741824 // This will become a parameter of the test

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

volatile bool g_running  = true;
volatile bool queue_stop = false;

// A simple macro used to check if there are enough command line args
#define ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, argName)                                           \
    if (i + 1 >= argc) {                                                                           \
        usage(argc, argv);                                                                         \
        fprintf(stderr, "! Error: missing value for %s argument\n", argName);                      \
        return false;                                                                              \
    }

#define MSG              1024
#define MAX_PAYLOAD_SIZE MR_SIZE
#define MIN_PAYLOAD_SIZE 1

typedef enum role {
    role_client,
    role_server,
    role_ping,
    role_pong,
} role_t;

static char *role_strings[] = {"CLIENT", "SERVER", "PING", "PONG"};

typedef struct test_config {
    role_t   role;
    char     provider_name[FI_NAME_MAX];
    char     domain_name[FI_NAME_MAX];
    char     remote_endpoint[FI_NAME_MAX];
    uint64_t payload_size;
    uint64_t sleep_time;
    uint64_t max_msg;
    uint16_t burst_size;
    uint16_t port_id;
} test_config_t;

/***Global states */
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

//--------------------------------------------------------------------------------------------------
void usage(int argc, char *argv[]) {
    printf("Usage: %s [MODE] [PROVIDER] [DOMAIN] [REMOTE] [OPTIONS]                  \n"
           "MODE: client|server|ping|pong                \n"
           "PROVIDER: dpdk|verbs|tcp|sockets|shm         \n"
           "DOMAIN: <provider specific, e.g. PCI address>\n"
           "REMOTE: <ip:port> if \"client\" or \"ping\"  \n"
           "OPTIONS:                                     \n"
           "-h: display this message and exit            \n"
           "-s: message payload size in bytes            \n"
           "-n: max messages to send (0 = no limit)      \n"
           "-b: burst size for receive (server only)     \n"
           "-r: configure sleep time (s) in send         \n",
           argv[0]);
}

//--------------------------------------------------------------------------------------------------
static inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

//--------------------------------------------------------------------------------------------------
int parse_arguments(int argc, char *argv[], test_config_t *config) {
    int i = 0;

    /* Argument number */
    if (argc < 4) {
        fprintf(stderr, "! Invalid number of arguments\n"
                        "! You must specify at least the running MODE\n"
                        "! You must specify at least the libfabric PROVIDER\n"
                        "! You must specify at least the libfabric DOMAIN\n"
                        "! You must specify at least the libfabric REMOTE_ENDPOINT\n");
        return -1;
    }
    i += 4;

    /* Default values */
    config->role         = role_server;
    config->payload_size = MSG;
    config->sleep_time   = 0;
    config->max_msg      = 0;
    config->burst_size   = 8;
    config->port_id      = 0;

    /* Test role (mandatory argument) */
    if (!strcmp(argv[1], "server")) {
        config->role = role_server;
    } else if (!strcmp(argv[1], "client")) {
        config->role = role_client;
    } else if (!strcmp(argv[1], "ping")) {
        config->role = role_ping;
    } else if (!strcmp(argv[1], "pong")) {
        config->role = role_pong;
    } else if (!strncmp(argv[1], "-h", 2) || !strncmp(argv[1], "--help", 6)) {
        return -1; // Success, but termination required
    } else {
        fprintf(stderr, "Unrecognized argument: %s\n", argv[1]);
        return -1;
    }

    /* Provider name (mandatory argument) */
    // Possible values: "dpdk", "verbs", "tcp", "sockets", "shm"
    if (!strcmp(argv[2], "dpdk") || !strcmp(argv[2], "verbs") || !strcmp(argv[2], "tcp") ||
        !strcmp(argv[2], "sockets") || !strcmp(argv[2], "shm"))
    {
        strcpy(config->provider_name, argv[2]);
    } else {
        fprintf(stderr, "Unrecognized provider name: %s\n", argv[2]);
        return -1;
    }

    /* Domain name (mandatory argument) */
    strcpy(config->domain_name, argv[3]);

    /* Remote endpoint, if CLIENT or PING */
    if (config->role == role_client || config->role == role_ping) {
        if (argc < 5) {
            fprintf(stderr, "! Invalid number of arguments\n"
                            "! You must specify at least the libfabric REMOTE_ENDPOINT\n");
            return -1;
        }
        strcpy(config->remote_endpoint, argv[4]);
        i++;
    }

    /* Parse the optional arguments */
    for (; i < argc; ++i) {
        // Helper
        if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
            return -1; // Success, but termination required
        }
        // Message payload size
        if (!strncmp(argv[i], "-s", 2) || !strncmp(argv[i], "--size", 6)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--size")
            config->payload_size = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            if (config->payload_size < MIN_PAYLOAD_SIZE || config->payload_size > MAX_PAYLOAD_SIZE)
            {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Max number of messages
        if (!strncmp(argv[i], "-n", 2) || !strncmp(argv[i], "--num-msg", 9)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--num-msg")
            config->max_msg = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --num-msg option: %s\n", argv[i]);
                return -1;
            }
            if (config->max_msg < 0) {
                fprintf(stderr, "! max_msg: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Burst size
        if (!strncmp(argv[i], "-b", 2) || !strncmp(argv[i], "--burst-size", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--burst-size")
            config->burst_size = strtoul(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --burst-size option: %s\n", argv[i]);
                return -1;
            }
            if (config->burst_size <= 0) {
                fprintf(stderr, "! burst_size: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Sleep time
        if (!strncmp(argv[i], "-r", 2) || !strncmp(argv[i], "--sleep-time", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--sleep-time")
            config->sleep_time = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for sleep-time option: %s\n", argv[i]);
                return -1;
            }
            if (config->sleep_time < 0) {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
    }

    // Print out the configuration
    printf("Running with the following arguments:   \n"
           "\tRole............. : %s                \n"
           "\tProvider name.... : %s                \n"
           "\tDomain name...... : %s                \n"
           "\tPayload size..... : %lu               \n"
           "\tMax messages..... : %lu               \n"
           "\tSleep time....... : %ld               \n\n",
           role_strings[config->role], config->provider_name, config->domain_name,
           config->payload_size, config->max_msg, config->sleep_time);

    return 0;
} // parse_arguments

//--------------------------------------------------------------------------------------------------
static int pagesz_flags(uint64_t page_sz) {
    /* as per mmap() manpage, all page sizes are log2 of page size
     * shifted by MAP_HUGE_SHIFT
     */
    int log2 = rte_log2_u64(page_sz);

    return (log2 << HUGE_SHIFT);
}

//--------------------------------------------------------------------------------------------------
int start_server_side() {
    int ret;

    /** Initialize the event queue  */
    ret = fi_eq_open(g_ctxt.fabric, &(g_ctxt.eq_attr), &(g_ctxt.peq), NULL);
    if (ret) {
        printf("fi_eq_open() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    /** Initialize the event queue, initialize and configure pep  */
    // Create passive EP (=> similar to server socket)
    ret = fi_passive_ep(g_ctxt.fabric, g_ctxt.fi, &(g_ctxt.pep), NULL);
    if (ret) {
        printf("fi_passive_ep() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    // Bind the passive endpoint to the event queue
    ret = fi_pep_bind(g_ctxt.pep, &(g_ctxt.peq->fid), 0);
    if (ret) {
        printf("fi_pep_bind() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    // Listen for incoming connections
    ret = fi_listen(g_ctxt.pep);
    if (ret) {
        printf("fi_listen() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    // Get the local address
    ret = fi_getname(&(g_ctxt.pep->fid), g_ctxt.pep_addr, &(g_ctxt.pep_addr_len));
    if (ret) {
        printf("fi_getname() failed: %s\n", fi_strerror(-ret));
        return ret;
    }
    if (g_ctxt.pep_addr_len > MAX_LF_ADDR_SIZE) {
        printf("local name is too big to fit in local buffer\n");
        return ret;
    }
    // Print the local address TODO: This should check the address format!!
    struct sockaddr_in *addr = (struct sockaddr_in *)g_ctxt.pep_addr;
    printf("Server server address: %s:%d\n", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    printf("Server started! Listening for incoming connections...\n");

    return 0;
}

//--------------------------------------------------------------------------------------------------
int init_active_ep(struct fi_info *fi, struct fid_ep **ep, struct fid_eq **eq) {
    int ret;

    ret = fi_domain(g_ctxt.fabric, g_ctxt.fi, &(g_ctxt.domain), NULL);
    if (ret) {
        printf("fi_domain() failed: %s\n", fi_strerror(-ret));
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

    /* Create an event queue */
    ret = fi_eq_open(g_ctxt.fabric, &(g_ctxt.eq_attr), eq, NULL);
    if (ret) {
        printf("fi_eq_open() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    /* Open an endpoint */
    ret = fi_endpoint(g_ctxt.domain, fi, ep, NULL);
    if (ret) {
        printf("fi_endpoint() failed: %s\n", fi_strerror(-ret));
        return ret;
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

//--------------------------------------------------------------------------------------------------
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

//--------------------------------------------------------------------------------------------------
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

//--------------------------------------------------------------------------------------------------
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

//--------------------------------------------------------------------------------------------------
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

//--------------------------------------------------------------------------------------------------
void do_server(test_config_t *params) {
    int ret;

    ret = start_server_side();
    if (ret) {
        printf("start_server_side() failed: %s\n", fi_strerror(-ret));
        exit(2);
    }

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

    // Allocate a memory region
    ret = register_memory_region();
    if (ret != 0) {
        printf("register_memory_region failed: %s\n", fi_strerror(-ret));
        exit(1);
    }

    // TODO: post a recv?

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

    // Prepare message
    struct iovec  msg_iov;
    struct fi_msg msg;
    msg_iov.iov_base = g_mr.buffer;
    msg_iov.iov_len  = params->payload_size;
    bzero((void *)g_mr.buffer, params->payload_size);
    msg.msg_iov   = &msg_iov;
    void *desc    = fi_mr_desc(g_mr.mr);
    msg.desc      = &desc;
    msg.iov_count = 1;
    msg.addr      = 0;
    msg.context   = NULL;

    // Server loop
    struct fi_cq_msg_entry comp;
    fi_addr_t              src_addr;
    uint64_t               first_time = 0, last_time = 0;
    uint16_t               nb_rx   = 0;
    uint64_t               counter = 0;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        // Post a receive request
        do {
            msg.msg_iov = &msg_iov;
            ret         = fi_recvmsg(ep, &msg, 0);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("fi_recvmsg() failed: %s\n", fi_strerror(-ret));
                exit(2);
            }
        } while (ret == -FI_EAGAIN);

        // Get the associated completion
        do {
            ret = fi_cq_readfrom(g_ctxt.rx_cq, &comp, 1, &src_addr);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("CQ read failed: %s", fi_strerror(-ret));
                break;
            }
        } while (ret == -FI_EAGAIN);

        if (counter == 0) {
            first_time = get_clock_realtime_ns();
        }
        counter++;
    }
    last_time = get_clock_realtime_ns();

    /* Compute results */
    uint64_t elapsed_time_ns = last_time - first_time;
    double   mbps =
        ((counter * params->payload_size * 8) * ((double)1e3)) / ((double)elapsed_time_ns);
    double throughput = ((counter) * ((double)1e3)) / ((double)elapsed_time_ns);
    fprintf(stdout, "%lu,%lu,%.3f,%.3f,%.3f\n", counter, params->payload_size,
            (double)elapsed_time_ns / ((double)1e6), throughput, mbps);

    fi_close(&ep->fid);
    fi_close(&eq->fid);

    printf("Server exiting...\n");
    return;
}

//--------------------------------------------------------------------------------------------------
void do_client(test_config_t *params) {
    int ret;

    // Active endpoint and associated event queue
    struct fid_ep *ep;
    struct fid_eq *eq;

    /* Initialize the event queue  */
    ret = fi_eq_open(g_ctxt.fabric, &(g_ctxt.eq_attr), &eq, NULL);
    if (ret) {
        printf("fi_eq_open() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    if (init_active_ep(g_ctxt.fi, &ep, &eq)) {
        printf("failed to initialize client endpoint.\n");
        exit(2);
    }

    // Allocate a memory region
    ret = register_memory_region();
    if (ret != 0) {
        printf("register_memory_region failed: %s\n", fi_strerror(-ret));
        exit(1);
    }

    // Connect to the server
    struct fi_eq_cm_entry entry;
    uint32_t              event;

    struct addrinfo *svr_ai = parse_ip_port_string(params->remote_endpoint);
    if (!svr_ai) {
        fprintf(stderr, "%s cannot get server address from string:%s.\n", __func__,
                params->remote_endpoint);
        return;
    }

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

    // Prepare message
    struct iovec  msg_iov;
    struct fi_msg msg;
    msg_iov.iov_base = g_mr.buffer;
    msg_iov.iov_len  = params->payload_size;
    bzero((void *)g_mr.buffer, params->payload_size);
    msg.msg_iov   = &msg_iov;
    void *desc    = fi_mr_desc(g_mr.mr);
    msg.desc      = &desc;
    msg.iov_count = 1;
    msg.addr      = 0;
    msg.context   = NULL;

    // Fill the buffer with random content
    memset(g_mr.buffer, 'a', msg_iov.iov_len);

    // Client loop
    uint64_t               tx_time;
    uint64_t               counter = 0;
    struct fi_cq_msg_entry comp;
    fi_addr_t              src_addr;

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        if (params->sleep_time) {
            sleep(params->sleep_time);
        }
        tx_time = get_clock_realtime_ns();

        // Post a send request
        msg.msg_iov = &msg_iov;
        ret         = fi_sendmsg(ep, &msg, FI_COMPLETION);
        if (ret) {
            printf("fi_sendmsg() failed: %s\n", fi_strerror(-ret));
            printf("Insert a message size: ");
            continue;
        }

        // Get send completion
        do {
            ret = fi_cq_readfrom(g_ctxt.tx_cq, &comp, 1, &src_addr);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("CQ read failed: %s", fi_strerror(-ret));
                break;
            }
        } while (ret == -FI_EAGAIN);

        counter++;
    }

    fi_shutdown(ep, 0);

    fi_close(&ep->fid);
    fi_close(&eq->fid);

    printf("Client disconnected, exiting...\n");
    return;
}

void do_ping(test_config_t *params) {
    int ret;

    // Active endpoint and associated event queue
    struct fid_ep *ep;
    struct fid_eq *eq;

    /* Initialize the event queue  */
    ret = fi_eq_open(g_ctxt.fabric, &(g_ctxt.eq_attr), &eq, NULL);
    if (ret) {
        printf("fi_eq_open() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    struct addrinfo *svr_ai = parse_ip_port_string(params->remote_endpoint);
    if (!svr_ai) {
        fprintf(stderr, "%s cannot get server address from string:%s.\n", __func__,
                params->remote_endpoint);
        return;
    }

    g_ctxt.fi->dest_addr = malloc(svr_ai->ai_addrlen);
    memcpy(g_ctxt.fi->dest_addr, svr_ai->ai_addr, svr_ai->ai_addrlen);
    g_ctxt.fi->dest_addrlen = svr_ai->ai_addrlen;
    g_ctxt.fi->addr_format  = FI_SOCKADDR_IN;

    if (init_active_ep(g_ctxt.fi, &ep, &eq)) {
        printf("failed to initialize ping endpoint.\n");
        exit(2);
    }

    // Allocate a memory region
    ret = register_memory_region();
    if (ret != 0) {
        printf("register_memory_region failed: %s\n", fi_strerror(-ret));
        exit(1);
    }

    // Connect to the server
    struct fi_eq_cm_entry entry;
    uint32_t              event;

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
    printf("Ping client connected!\n");

    // Prepare message. We use the same area for ping/pong, should be fine for this simple test.
    struct iovec  msg_iov;
    struct fi_msg msg;
    msg_iov.iov_base = g_mr.buffer;
    msg_iov.iov_len  = params->payload_size;
    bzero((void *)g_mr.buffer, params->payload_size);
    msg.msg_iov   = &msg_iov;
    void *desc    = fi_mr_desc(g_mr.mr);
    msg.desc      = &desc;
    msg.iov_count = 1;
    msg.addr      = 0;
    msg.context   = NULL;

    // Fill the buffer with random content
    memset(g_mr.buffer, 'a', msg_iov.iov_len);

    // Ping loop
    uint64_t               send_time, response_time, latency;
    uint64_t               counter = 0;
    struct fi_cq_msg_entry comp;
    fi_addr_t              src_addr;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        send_time = get_clock_realtime_ns();

        // Post a receive request: Pong
        do {
            msg.msg_iov = &msg_iov;
            ret         = fi_recvmsg(ep, &msg, 0);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("fi_recvmsg() failed: %s\n", fi_strerror(-ret));
                exit(2);
            }
        } while (ret == -FI_EAGAIN);

        // Post a send request: PING!
        msg.msg_iov = &msg_iov;
        ret         = fi_sendmsg(ep, &msg, FI_COMPLETION);
        if (ret) {
            printf("fi_sendmsg() failed: %s\n", fi_strerror(-ret));
            exit(2);
        }

        // Get receive completion
        do {
            ret = fi_cq_read(g_ctxt.rx_cq, &comp, 1);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("CQ read failed: (%d) %s\n", ret, fi_strerror(-ret));
                break;
            }
        } while (ret == -FI_EAGAIN);

        // Compute latency
        response_time = get_clock_realtime_ns();
        // PRINT LATENCY BREAKDOWN
        // printf("[%ld] Send     %lu\n", counter, send_time);
        // fi_control(&g_ctxt.fabric->fid, counter, 0); // Dummy call to allow printing timestamps
        // printf("[%ld] Recv     %lu\n", counter, response_time);
        latency = response_time - send_time;
        // Print the latency in us
        // fprintf(stdout, "[%ld] %.3f\n", counter, (float)latency / 1000.0F);
        fprintf(stdout, "%.3f\n", (float)latency / 1000.0F);

        counter++;
    }
}

//--------------------------------------------------------------------------------------------------
void do_pong(test_config_t *params) {
    int ret;

    ret = start_server_side();
    if (ret) {
        printf("start_server_side() failed: %s\n", fi_strerror(-ret));
        exit(2);
    }

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

    // Allocate a memory region
    ret = register_memory_region();
    if (ret != 0) {
        printf("register_memory_region failed: %s\n", fi_strerror(-ret));
        exit(1);
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
    printf("Pong server connected!\n");

    // Prepare message. We use the same area for ping/pong, should be fine for this simple test.
    struct iovec  msg_iov;
    struct fi_msg msg;
    msg_iov.iov_base = g_mr.buffer;
    msg_iov.iov_len  = params->payload_size;
    bzero((void *)g_mr.buffer, params->payload_size);
    msg.msg_iov   = &msg_iov;
    void *desc    = fi_mr_desc(g_mr.mr);
    msg.desc      = &desc;
    msg.iov_count = 1;
    msg.addr      = 0;
    msg.context   = NULL;

    // Fill the buffer with random content
    memset(g_mr.buffer, 'a', msg_iov.iov_len);

    // Pong loop
    uint64_t               send_time, response_time, latency;
    uint64_t               counter = 0;
    struct fi_cq_msg_entry comp;
    fi_addr_t              src_addr;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        if (params->sleep_time) {
            sleep(params->sleep_time);
        }
        send_time = get_clock_realtime_ns();

        // Post a receive request: Pong
        do {
            msg.msg_iov = &msg_iov;
            ret         = fi_recvmsg(ep, &msg, 0);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("fi_recvmsg() failed: %s\n", fi_strerror(-ret));
                exit(2);
            }
        } while (ret == -FI_EAGAIN);

        // Get receive completion
        do {
            ret = fi_cq_read(g_ctxt.rx_cq, &comp, 1);
            if (ret < 0 && ret != -FI_EAGAIN) {
                printf("CQ read failed: (%d) %s\n", ret, fi_strerror(-ret));
                break;
            }
        } while (ret == -FI_EAGAIN);

        // Post a send request: PING!
        msg.msg_iov = &msg_iov;
        ret         = fi_sendmsg(ep, &msg, FI_COMPLETION);
        if (ret) {
            printf("fi_sendmsg() failed: %s\n", fi_strerror(-ret));
            printf("Insert a message size: ");
            continue;
        }

        // No need for completion
        counter++;
    }

    fi_close(&ep->fid);
    fi_close(&eq->fid);

    printf("Server exiting...\n");
    return;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char **argv) {
    int ret;

    // Parse the arguments
    test_config_t params;
    if (parse_arguments(argc, argv, &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    // Initialize the Libfabric hints to ask for the right provider, fabric, domain.
    default_context(params.provider_name, params.domain_name);

    // Get the fabric info
    ret = fi_getinfo(LF_VERSION, NULL, NULL, 0, g_ctxt.hints, &g_ctxt.fi);
    if (ret != 0) {
        printf("%s:%s fi_getinfo failed: %s\n", __FILE__, __func__, fi_strerror(-ret));
        exit(1);
    }

    /* Initialize the fabric */
    ret = fi_fabric(g_ctxt.fi->fabric_attr, &(g_ctxt.fabric), NULL);

    if (ret) {
        printf("fi_fabric() failed: %s\n", fi_strerror(-ret));
        return ret;
    }

    // Do test
    if (params.role == role_client) {
        do_client(&params);
    } else if (params.role == role_server) {
        do_server(&params);
    } else if (params.role == role_ping) {
        do_ping(&params);
    } else if (params.role == role_pong) {
        do_pong(&params);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

cleanup_and_exit:
    fi_freeinfo(g_ctxt.fi);
    return 0;
}
