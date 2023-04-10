#include "fi_dpdk.h"
#include <confuse.h>

// ================ The global configuration ================
struct cfg_t *dpdk_config = NULL;

cfg_t *dpdk_domain_config(const char *domain_name) {
    int ndom = cfg_size(dpdk_config, CFG_OPT_DOMAIN);
    for (int i = 0; i < ndom; i++) {
        cfg_t *domain_config = cfg_getnsec(dpdk_config, CFG_OPT_DOMAIN, i);
        if (strcmp(cfg_title(domain_config), domain_name) == 0) {
            return domain_config;
        }
    }
    return NULL;
}

// ================ Provider Initialization Functions =================
static void fi_dpdk_fini(void) {

    rte_eal_cleanup();

    if (dpdk_config) {
        cfg_free(dpdk_config);
        dpdk_config = NULL;
    }
}

// This function is implemented in dpdk_info.c
extern int dpdk_getinfo(uint32_t version, const char *node, const char *service, uint64_t flags,
                        const struct fi_info *hints, struct fi_info **info);
struct fi_provider dpdk_prov = {
    .name       = "dpdk",
    .version    = OFI_VERSION_DEF_PROV,
    .fi_version = OFI_VERSION_LATEST,
    .getinfo    = dpdk_getinfo,
    .fabric     = dpdk_create_fabric,
    .cleanup    = fi_dpdk_fini,
};

static char *cfg_file              = NULL;
static char *default_dpdk_cfg_file = "./libfabric.dpdk.cfg";

static void dpdk_init_env(void) {
    /* the only thing we need as a libfabric parameter is the location of dpdk config file
     * Just set FI_DPDK_CFG_FILE in the environment variable, or it will just use the
     * "libfabric.dpdk.cfg"
     */
    fi_param_define(&dpdk_prov, "cfg_file", FI_PARAM_STRING,
                    "Specify the dpdk configuration file location. "
                    "(default: ./libfabric.dpdk.cfg)");
    fi_param_get_str(&dpdk_prov, "cfg_file", &cfg_file);
    if (!cfg_file) {
        cfg_file = default_dpdk_cfg_file;
    }
}

static void dpdk_load_cfg() {
    static struct cfg_opt_t domain_opts[] = {
        CFG_STR(CFG_OPT_DOMAIN_IP, NULL, CFGF_NODEFAULT),
        CFG_INT(CFG_OPT_DOMAIN_CM_PORT, 2509, CFGF_NONE),
        CFG_INT(CFG_OPT_DOMAIN_CM_RING_SIZE, 16, CFGF_NONE),
    };
    static struct cfg_opt_t ops[] = {CFG_STR_LIST(CFG_OPT_DPDK_ARGS, "{libfabric}", CFGF_NONE),
                                     CFG_INT(CFG_OPT_DEFAULT_CM_PORT, 2509, CFGF_NONE),
                                     CFG_INT(CFG_OPT_DEFAULT_CM_RING_SIZE, 16, CFGF_NONE),
                                     CFG_SEC(CFG_OPT_DOMAIN, domain_opts, CFGF_MULTI | CFGF_TITLE),
                                     CFG_END()};

    dpdk_config = cfg_init(ops, CFGF_NONE);
    if (cfg_file) {
        // read configuration file
        if (cfg_parse(dpdk_config, cfg_file) != CFG_SUCCESS) {
            DPDK_WARN(FI_LOG_CORE,
                      "Failed loading configuration file: %s, falling back to defaults", cfg_file);
        }
    }
}
// Entry point for the libfabric provider
DPDK_INI {
    // set up the environment
    dpdk_init_env();
    dpdk_load_cfg();

    // Initialize the EAL
    int    argc = cfg_size(dpdk_config, CFG_OPT_DPDK_ARGS) + 1;
    char   appname[64];
    char **argv = (char **)calloc(argc, sizeof(char *));
    if (!argv) {
        DPDK_WARN(FI_LOG_CORE, "Cannot allocate space for args.\n");
        goto error_group_1;
    }
    sprintf(appname, "pid-%d", getpid());
    argv[0] = appname;
    for (int idx = 1; idx < argc; idx++) {
        argv[idx] = cfg_getnstr(dpdk_config, CFG_OPT_DPDK_ARGS, idx - 1);
    }

    if (rte_eal_init(argc, argv) < 0) {
        DPDK_WARN(FI_LOG_CORE, "Error with EAL initialization\n");
        goto error_group_2;
    }
    free(argv);

    // initialize dpdk info
    dpdk_init_info(&(dpdk_util_prov.info));

    return &dpdk_prov;
error_group_2:
    free(argv);
error_group_1:
    if (dpdk_config) {
        cfg_free(dpdk_config);
        dpdk_config = NULL;
    }
    return NULL;
}
