#include "fi_dpdk.h"
#include <confuse.h>

// ================ The global variables ================
struct dpdk_params_t dpdk_params;

// ================ Provider Initialization Functions =================
static void fi_dpdk_fini(void) {

    rte_eal_cleanup();
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

static char*  cfg_file = NULL;
static char*  default_dpdk_cfg_file = "./libfabric.dpdk.cfg";

static void dpdk_init_env(void) {
    /* the only thing we need as a libfabric parameter is the location of dpdk config file 
     * Just set FI_DPDK_CFG_FILE in the environment variable, or it will just use the 
     * "libfabric.dpdk.cfg"
     */
    fi_param_define(&dpdk_prov, "cfg_file", FI_PARAM_STRING,
                    "Specify the dpdk configuration file location. "
                    "(default: ./libfabric.dpdk.cfg)");
    fi_param_get_str(&dpdk_prov, "cfg_file", &cfg_file);
    if(!cfg_file) {
        cfg_file = default_dpdk_cfg_file;
    }
    
    /* set the dpdk base port
    fi_param_define(&dpdk_prov, "base_port", FI_PARAM_INT, "define dpdk base port");
    fi_param_get_int(&dpdk_prov, "base_port", &dpdk_params.base_port);
    if (dpdk_params.base_port < 0 && dpdk_params.base_port > 65535) {
        DPDK_WARN(FI_LOG_FABRIC,
                  "User provided base_port %d is invalid."
                  " Falling back to default base_port:%d instead. \n",
                  dpdk_params.base_port, DEFAULT_DPDK_BASE_PORT);
        dpdk_params.base_port = DEFAULT_DPDK_BASE_PORT;
    }
    */

    /* set the dpdk cm ring size
    fi_param_define(&dpdk_prov, "cm_ring_size", FI_PARAM_SIZE_T, "define dpdk cm ring size");
    fi_param_get_size_t(&dpdk_prov, "cm_ring_size", &dpdk_params.cm_ring_size);
    */
}

static void dpdk_load_cfg() {
    static struct cfg_opt_t ops [] = {
#define CFG_OPT_DPDK_ARGS       "dpdk_args"
        CFG_STR(CFG_OPT_DPDK_ARGS,      "libfabric",     CFGF_NONE),
#define CFG_OPT_CM_PORT         "connection_management_port"
        CFG_INT(CFG_OPT_CM_PORT,        2509,   CFGF_NONE),
#define CFG_OPT_CM_RING_SIZE    "connection_management_ring_size"
        CFG_INT(CFG_OPT_CM_RING_SIZE,   16,     CFGF_NONE),
        CFG_END()
    };

    cfg_t* cfg = cfg_init(ops,CFGF_NONE);
    if (cfg_file) {
        // read configuration file
        if(cfg_parse(cfg, cfg_file) != CFG_SUCCESS) {
            DPDK_WARN(FI_LOG_CORE,"Failed loading configuration file: %s, falling back to defaults", cfg_file);
        }
    }

    // set dpdk params
    dpdk_params.dpdk_args = cfg_getstr(cfg,CFG_OPT_DPDK_ARGS);
    dpdk_params.cm_port = cfg_getint(cfg,CFG_OPT_CM_PORT);
    if (dpdk_params.cm_port < 0 || dpdk_params.cm_port > 65535) {
        DPDK_WARN(FI_LOG_FABRIC,
                  "User provided " CFG_OPT_CM_PORT " %ld is invalid."
                  " Falling back to default port:%d instead. \n",
                  dpdk_params.cm_port, 2509);
        dpdk_params.cm_port = 2509;
    }
    dpdk_params.cm_ring_size = cfg_getint(cfg,CFG_OPT_CM_RING_SIZE);
}
// Entry point for the libfabric provider
DPDK_INI {
    // set up the environment
    dpdk_init_env();
    dpdk_load_cfg();

    // load configuration file.
    int     argc = 0;
    char*   argv[64]; // 64 tokens should be enough.
    int     apos = 0;
    int     state = 0; /* 0 - space; 1 - token; */
    char*   dpdk_args = strdup(dpdk_params.dpdk_args);
    if (!dpdk_args) {
        DPDK_WARN(FI_LOG_CORE, "%s: strdup returns NULL.\n", __func__);
        return NULL;
    }
    while(apos <= strlen(dpdk_params.dpdk_args)) {
        switch(state) {
        case 0: /* space state */
            if (dpdk_args[apos] != ' ' && dpdk_args[apos] != '\0') {
                argv[argc] = &dpdk_args[apos];
                state=1-state; /*state --> token*/
            } else {
                dpdk_args[apos] = '\0';
            }
            break;
        case 1:
            if (dpdk_args[apos] == ' ' || dpdk_args[apos] == '\0') {
                dpdk_args[apos] = '\0';
                argc ++;
                state=1-state; /*state --> space*/
            }
            break;
        default:
            // unlikely
            DPDK_WARN(FI_LOG_CORE, "%s Unlikely: parser state is %d.\n", __func__, state);
            break;
        }
        apos ++;
    }
    argc ++;

    // TODO: Limit the number of cores to dedicate to DPDK!

    // Initialize the EAL
    if (rte_eal_init(argc, argv) < 0) {
        DPDK_WARN(FI_LOG_CORE, "Error with EAL initialization\n");
        return NULL;
    }

    free(dpdk_args);

    // initialize dpdk info
    dpdk_init_info(&(dpdk_util_prov.info));

    return &dpdk_prov;
}
