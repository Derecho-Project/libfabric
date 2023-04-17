#include "fi_dpdk.h"

static int dpdk_fabric_close(fid_t fid) {
    int                 ret;
    struct dpdk_fabric *fabric;

    fabric = container_of(fid, struct dpdk_fabric, util_fabric.fabric_fid.fid);

    ret = ofi_fabric_close(&fabric->util_fabric);
    if (ret)
        return ret;

    free(fabric);
    return 0;
}

struct fi_ops_fabric dpdk_fabric_ops = {.size       = sizeof(struct fi_ops_fabric),
                                        .domain     = dpdk_domain_open,
                                        .passive_ep = dpdk_passive_ep,
                                        .eq_open    = dpdk_eq_open,
                                        .wait_open  = ofi_wait_fd_open,
                                        .trywait    = ofi_trywait,
                                        .domain2    = fi_no_domain2};

struct fi_ops dpdk_fabric_fi_ops = {.size     = sizeof(struct fi_ops),
                                    .close    = dpdk_fabric_close,
                                    .bind     = fi_no_bind,
                                    .control  = fi_no_control,
                                    .ops_open = fi_no_ops_open,
                                    .ops_set  = fi_no_ops_set};

static struct rte_flow *generate_cm_flow(uint16_t port_id, uint16_t rx_queue_id, uint32_t ip,
                                         uint16_t port, struct rte_flow_error *error) {
    struct rte_flow_attr         attr;
    struct rte_flow_item         pattern[4];
    struct rte_flow_item_ipv4    ipv4_spec;
    struct rte_flow_item_ipv4    ipv4_mask;
    struct rte_flow_item_udp     udp_spec;
    struct rte_flow_item_udp     udp_mask;
    struct rte_flow_action       action[2];
    struct rte_flow             *flow  = NULL;
    struct rte_flow_action_queue queue = {.index = rx_queue_id};
    int                          err;

    bzero(&attr, sizeof(attr));
    bzero(pattern, sizeof(pattern));
    bzero(action, sizeof(action));

    // rule attr
    attr.ingress = 1;

    // action sequence
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    // patterns
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    bzero(&ipv4_spec, sizeof(ipv4_spec));
    ipv4_spec.hdr.next_proto_id = 0x11; // UDP
    ipv4_spec.hdr.dst_addr      = ip;
    bzero(&ipv4_mask, sizeof(ipv4_mask));
    ipv4_mask.hdr.next_proto_id = 0xff; // UDP Mask
    ipv4_mask.hdr.dst_addr      = 0xffffffff;
    pattern[1].type             = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec             = &ipv4_spec;
    pattern[1].mask             = &ipv4_mask;
    pattern[1].last             = NULL;

    bzero(&udp_spec, sizeof(udp_spec));
    udp_spec.hdr.dst_port = port;
    bzero(&udp_mask, sizeof(udp_mask));
    udp_mask.hdr.dst_port = 0xffff;
    pattern[2].type       = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec       = &udp_spec;
    pattern[2].mask       = &udp_mask;
    pattern[2].last       = NULL;

    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    err = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!err) {
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    }

    return flow;
}

/**
 * clean up a single domain resource object
 * @param res   pointer to a single res;
 */
static int release_domain_resources(struct dpdk_domain_resources *res) {
    if (res) {
        bool pep_busy    = false;
        bool domain_busy = false;
        ofi_mutex_lock(&res->pep_lock);
        pep_busy = (res->pep != NULL);
        ofi_mutex_unlock(&res->pep_lock);
        if (pep_busy) {
            DPDK_WARN(FI_LOG_FABRIC,
                      "Cannot release domain resources on %s, "
                      "because its passive endpoint is active.\n",
                      res->domain_name);
            return -FI_EBUSY;
        }
        ofi_mutex_lock(&res->domain_lock);
        domain_busy = (res->domain != NULL);
        ofi_mutex_unlock(&res->domain_lock);
        if (domain_busy) {
            DPDK_WARN(FI_LOG_FABRIC,
                      "Cannot release domain resources on %s, "
                      "because the domain is active.\n",
                      res->domain_name);
            return -FI_EBUSY;
        }

        // STEP 0 - close the port
        rte_eth_dev_close(res->port_id);
        // STEP 1 - close rings
        if (res->cm_tx_ring) {
            rte_ring_free(res->cm_tx_ring);
        }
        // STEP 2 - close pool
        if (res->cm_pool) {
            rte_mempool_free(res->cm_pool);
        }
    }
    return FI_SUCCESS;
}
/**
 * Clean up the domain resources list
 *
 * @param res_list pointer to the list header.
 */
static int release_res_list(struct dpdk_domain_resources *res_list) {
    while (res_list->next) {
        struct dpdk_domain_resources *res = res_list->next;
        int                           ret = release_domain_resources(res);
        if (ret != 0) {
            return ret;
        }
        res_list = res->next;
    }
    return FI_SUCCESS;
}

static void *connection_manager(void *arg) {
    struct dpdk_fabric *fabric = (struct dpdk_fabric *)arg;
    DPDK_DBG(FI_LOG_EP_CTRL, "connection manager thread started.\n");
    while (atomic_load(&fabric->active)) {
        DPDK_DBG(FI_LOG_EP_CTRL, "connection manager thread looping...\n");
        ofi_mutex_lock(&fabric->domain_res_list_lock);
        struct dpdk_domain_resources *res = fabric->domain_res_list.next;
        DPDK_DBG(FI_LOG_EP_CTRL, "connection manager starts with res=%p.\n", res);
        bool is_busy = false;
        while (res) {
            DPDK_DBG(FI_LOG_EP_CTRL, "connection manager is processing res=%p.\n", res);
            struct rte_mbuf *pkts[8];
            uint16_t         npkts;
            // incoming
            while ((npkts = rte_eth_rx_burst(res->port_id, res->cm_rxq_id, pkts, 8)) > 0) {
                DPDK_DBG(FI_LOG_EP_CTRL, "connection manager detected %u incoming packets.\n",
                         npkts);
                is_busy = true;
                for (uint16_t i = 0; i < npkts; i++) {
                    dpdk_cm_recv(pkts[i], res);
                    rte_pktmbuf_free(pkts[i]);
                }
            }
            // outgoing
            while ((npkts = rte_ring_sc_dequeue_burst(res->cm_tx_ring, (void **)pkts, 8, NULL)) > 0)
            {
                DPDK_DBG(FI_LOG_EP_CTRL, "connection manager detected %u outgoing packets.\n",
                         npkts);
                is_busy        = true;
                uint16_t nsent = 0;
                while (nsent < npkts) {
                    nsent +=
                        rte_eth_tx_burst(res->port_id, res->cm_txq_id, &pkts[nsent], npkts - nsent);
                }
            }
            res = res->next;
        }
        ofi_mutex_unlock(&fabric->domain_res_list_lock);
        if (!is_busy) {
            usleep(100000); // sleep for 100 ms
        }
    }
    DPDK_DBG(FI_LOG_EP_CTRL, "connection manager thread stopped.\n");
    return NULL;
}

int create_dpdk_domain_resources(struct fi_info *info, struct dpdk_domain_resources **pres) {
    int err = FI_SUCCESS;

    if (!info->domain_attr || !info->domain_attr->name) {
        DPDK_WARN(FI_LOG_FABRIC,
                  "Failed to create domain resources because domain name is invalid.\n");
        err = -FI_EINVAL;
        goto error_group_1;
    }

    uint16_t                port_id;
    bool                    port_found = false;
    struct rte_eth_dev_info devinfo;
    RTE_ETH_FOREACH_DEV(port_id) {
        err = rte_eth_dev_info_get(port_id, &devinfo);
        if (err != FI_SUCCESS) {
            DPDK_WARN(FI_LOG_FABRIC,
                      "Cannot get information of port_id:%d, error:%s. skipping...\n", port_id,
                      rte_strerror(rte_errno));
            continue;
        }
        if (strcmp(rte_dev_name(devinfo.device), info->domain_attr->name) == 0) {
            port_found = true;
            break;
        }
    }
    if (!port_found) {
        DPDK_WARN(FI_LOG_FABRIC,
                  "Failed to create domain resources because we cannot find domain:%s.\n",
                  info->domain_attr->name);
        err = -FI_EINVAL;
        goto error_group_1;
    }

    struct dpdk_domain_resources *res = calloc(1, sizeof(*res));
    if (!res) {
        DPDK_WARN(FI_LOG_FABRIC, "failed to allocate memory for domain connection manager: %s.\n",
                  strerror(errno));
        err = -FI_ENOMEM;
        goto error_group_1;
    }
    res->next = NULL;
    strcpy(res->domain_name, rte_dev_name(devinfo.device));
    res->domain_config = dpdk_domain_config(rte_dev_name(devinfo.device));
    res->port_id       = port_id;
    res->mtu           = RTE_MIN(1500, devinfo.max_mtu);

    err = rte_eth_macaddr_get(port_id, &res->local_eth_addr);
    if (err != 0) {
        DPDK_WARN(FI_LOG_FABRIC, "failed to get MAC address for port :%d. Error:%s \n", port_id,
                  rte_strerror(rte_errno));
        goto error_group_2;
    }

    if (info->src_addrlen == sizeof(struct sockaddr_in)) {
        // source address specified
        res->local_cm_addr = *(struct sockaddr_in *)info->src_addr;
    } else if (info->src_addrlen == 0 && res->domain_config) {
        res->local_cm_addr.sin_family = AF_INET;
        res->local_cm_addr.sin_port =
            rte_cpu_to_be_16((uint16_t)cfg_getint(res->domain_config, CFG_OPT_DOMAIN_CM_PORT));
        char *ipstr = cfg_getstr(res->domain_config, CFG_OPT_DOMAIN_IP);
        if (inet_pton(AF_INET, ipstr, &res->local_cm_addr.sin_addr) <= 0) {
            DPDK_WARN(FI_LOG_FABRIC, "failed to parse ip:%s, error:%s.\n", ipstr, strerror(errno));
            err = -FI_EINVAL;
            goto error_group_2;
        }
        info->src_addr = calloc(1, sizeof(struct sockaddr_in));
        if (!info->src_addr) {
            DPDK_WARN(FI_LOG_FABRIC, "failed to allocate space for info->src_addr \n");
            err = -FI_ENOMEM;
            goto error_group_2;
        }
        *(struct sockaddr_in *)info->src_addr = res->local_cm_addr;
        info->src_addrlen                     = sizeof(struct sockaddr_in);
    } else {
        DPDK_WARN(FI_LOG_FABRIC,
                  "failed to create domain resources because ip and port are not specified.\n");
        err = -FI_EINVAL;
        goto error_group_2;
    }

    res->data_rxq_id = 0;
    res->data_txq_id = 0;
    res->cm_rxq_id   = 1;
    res->cm_txq_id   = 1;

    int      socket_id = rte_eth_dev_socket_id(port_id);
    char     name[256];
    uint16_t cfg_cm_ring_size = 16;
    if (res->domain_config) {
        cfg_cm_ring_size = (uint16_t)cfg_getint(res->domain_config, CFG_OPT_DOMAIN_CM_RING_SIZE);
    }
    sprintf(name, "lf.%s.cmxr", res->domain_name);
    res->cm_tx_ring = rte_ring_create(name, cfg_cm_ring_size, rte_eth_dev_socket_id(port_id),
                                      RING_F_MP_RTS_ENQ | RING_F_SC_DEQ);
    if (!res->cm_tx_ring) {
        DPDK_WARN(FI_LOG_FABRIC, "failed to create cm_tx_ring, error:%s.\n",
                  rte_strerror(rte_errno));
        err = -FI_EFAULT;
        goto error_group_2;
    }
    sprintf(name, "lf.%s.cmp", res->domain_name);
    res->cm_pool = rte_pktmbuf_pool_create(
        name, 1024, 64, 0,
        RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) +
            sizeof(struct dpdk_cm_msg_hdr) + DPDK_MAX_CM_DATA_SIZE + RTE_ETHER_CRC_LEN,
        socket_id);
    if (!res->cm_pool) {
        DPDK_WARN(FI_LOG_FABRIC, "failed to create memory pool-%s, error:%s.\n", name,
                  rte_strerror(rte_errno));
        err = -FI_EFAULT;
        goto error_group_2;
    }
    // Configure device, initialize the rx/tx queues and the flows.
    struct rte_eth_conf port_conf;
    bzero(&port_conf, sizeof(port_conf));
    port_conf.rxmode.mtu = res->mtu;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (devinfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    if ((err = rte_eth_dev_configure(port_id, 2, 2, &port_conf)) != 0) {
        DPDK_WARN(FI_LOG_FABRIC, "rte_eth_dev_configure on port:%u failed with error:%s.\n",
                  port_id, rte_strerror(rte_errno));
        goto error_group_2;
    }
    if ((err = rte_eth_dev_set_mtu(port_id, res->mtu)) != 0) {
        DPDK_WARN(FI_LOG_FABRIC, "rte_eth_dev_set_mtu on port:%u to mtu-%u failed with error:%s.\n",
                  port_id, res->mtu, rte_strerror(rte_errno));
        goto error_group_3;
    }
    uint16_t nb_rxd = cfg_cm_ring_size;
    uint16_t nb_txd = cfg_cm_ring_size;
    if ((err = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd)) != 0) {
        DPDK_WARN(FI_LOG_FABRIC,
                  "rte_eth_dev_adjust_nb_rx_tx_desc ont port:%u failed with error:%s.\n", port_id,
                  rte_strerror(rte_errno));
        goto error_group_3;
    }
    // We use queue 0 for the data path and queue 1 for the control path.
    struct rte_eth_txconf txconf = devinfo.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < 2; q++) {
        if ((err = rte_eth_rx_queue_setup(port_id, q, nb_rxd, socket_id, NULL, res->cm_pool)) != 0)
        {
            DPDK_WARN(FI_LOG_FABRIC,
                      "rte_eth_rx_queue_setup failed on port:%u, qid:%u failed with error:%s.\n",
                      port_id, q, rte_strerror(rte_errno));
            goto error_group_3;
        }
        if ((err = rte_eth_tx_queue_setup(port_id, q, nb_txd, socket_id, &txconf)) != 0) {
            DPDK_WARN(FI_LOG_FABRIC,
                      "rte_eth_tx_queue_setup failed on port:%u, qid:%u failed with error:%s.\n",
                      port_id, q, rte_strerror(rte_errno));
            goto error_group_3;
        }
    }
    do {
        err = rte_eth_dev_start(port_id);
        if (err != -EAGAIN) {
            break;
        }
    } while (err == -EAGAIN);
    if (err) {
        DPDK_WARN(FI_LOG_FABRIC, "rte_eth_dev_start failed on port:%u, error:%s.\n", port_id,
                  rte_strerror(rte_errno));
        goto error_group_3;
    }
    if ((err = rte_eth_promiscuous_enable(port_id)) != 0) {
        DPDK_WARN(FI_LOG_FABRIC, "rte_eth_promiscuous failed on port:%u, error:%s.\n", port_id,
                  rte_strerror(rte_errno));
        goto error_group_3;
    }
    // Enable the flow
    struct rte_flow_error flow_error;
    if ((res->cm_flow = generate_cm_flow(port_id, 1, res->local_cm_addr.sin_addr.s_addr,
                                         res->local_cm_addr.sin_port, &flow_error)) == NULL)
    {
        DPDK_WARN(FI_LOG_FABRIC, "cm flow generation failed on port:%u, error:%s.\n", port_id,
                  flow_error.message ? flow_error.message : "unkown");
        goto error_group_3;
    }
    // session counter
    atomic_init(&res->cm_session_counter, 0);

    ofi_mutex_init(&res->pep_lock);
    ofi_mutex_init(&res->domain_lock);

    *pres = res;
    return FI_SUCCESS;

error_group_3:
    rte_eth_dev_close(res->port_id);
error_group_2:
    free(res);
error_group_1:
    return err;
}

int get_or_create_dpdk_domain_resources(struct dpdk_fabric *fabric, struct fi_info *info,
                                        struct dpdk_domain_resources **pres) {
    if (!info || !info->domain_attr || !info->domain_attr->name) {
        DPDK_WARN(FI_LOG_FABRIC, "Failed to get/create domain resources because"
                                 " domain is not specified in 'struct fi_info'.\n");
        return -FI_EINVAL;
    }

    // search for the domain resources
    int err = FI_SUCCESS;
    ofi_mutex_lock(&fabric->domain_res_list_lock);
    struct dpdk_domain_resources *res_list = &fabric->domain_res_list;
    struct dpdk_domain_resources *res      = NULL;
    while (res_list->next) {
        if (strcmp(info->domain_attr->name, res_list->next->domain_name) == 0) {
            res = res_list->next;
            break;
        }
        res_list = res_list->next;
    }

    if (res) {
        // check if res and fi_info is compatible or not.
        // here we only check the source address.
        if (info->src_addrlen > 0) {
            if (info->src_addrlen != sizeof(res->local_cm_addr)) {
                DPDK_WARN(FI_LOG_FABRIC,
                          "Information does not match:info->src_addrlen(%lu)!=%lu.\n",
                          info->src_addrlen, sizeof(res->local_cm_addr));
                err = -FI_EINVAL;
            } else if (((struct sockaddr_in *)info->src_addr)->sin_family !=
                           res->local_cm_addr.sin_family ||
                       ((struct sockaddr_in *)info->src_addr)->sin_port !=
                           res->local_cm_addr.sin_port ||
                       ((struct sockaddr_in *)info->src_addr)->sin_addr.s_addr !=
                           res->local_cm_addr.sin_addr.s_addr)
            {
                DPDK_WARN(FI_LOG_FABRIC, "Information does not match:info->src_addr.\n");
                err = -FI_EINVAL;
            }
        }
    } else {
        // try to create new domain resources object
        err = create_dpdk_domain_resources(info, &res);
        if (err != FI_SUCCESS) {
            DPDK_WARN(FI_LOG_FABRIC, "Failed to create domain resources for %s.\n",
                      info->domain_attr->name);
        } else {
            res->next                    = fabric->domain_res_list.next;
            fabric->domain_res_list.next = res;
        }
    }
    if (err == FI_SUCCESS) {
        acquire_dpdk_domain_resources(res);
        *pres = res;
    }
    ofi_mutex_unlock(&fabric->domain_res_list_lock);

    return err;
}

int dpdk_create_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric_fid, void *context) {
    struct dpdk_fabric *fabric;
    int                 ret;

    // STEP 1: common setup routine
    fabric = calloc(1, sizeof(*fabric));
    if (!fabric)
        return -FI_ENOMEM;

    ret = ofi_fabric_init(&dpdk_prov, dpdk_util_prov.info->fabric_attr, attr, &fabric->util_fabric,
                          context);
    if (ret)
        goto free;

    fabric->util_fabric.fabric_fid.fid.ops = &dpdk_fabric_fi_ops;
    fabric->util_fabric.fabric_fid.ops     = &dpdk_fabric_ops;
    *fabric_fid                            = &fabric->util_fabric.fabric_fid;

    // STEP 2: initialize the domain connection manager list
    ret = ofi_mutex_init(&fabric->domain_res_list_lock);
    if (ret) {
        goto free;
    }
    atomic_store(&fabric->active, true);

    // STEP 3: start connection manager control-thread
    if ((ret = rte_ctrl_thread_create(&fabric->cm_thread, "lf.cm", NULL, connection_manager,
                                      fabric)) != 0)
    {
        DPDK_WARN(FI_LOG_FABRIC, "failed to create cm thread. error:%s.\n",
                  rte_strerror(rte_errno));
        goto error_group_1;
    }

    return 0;

error_group_1:
    ofi_mutex_lock(&fabric->domain_res_list_lock);
    release_res_list(&fabric->domain_res_list);
    ofi_mutex_unlock(&fabric->domain_res_list_lock);
    ofi_mutex_destroy(&fabric->domain_res_list_lock);
    (void)ofi_fabric_close(&fabric->util_fabric);
free:
    free(fabric);
    return ret;
}
