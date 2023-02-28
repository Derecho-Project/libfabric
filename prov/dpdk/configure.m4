dnl Configury specific to the libfabric dpdk provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
dnl 
# TODO: detect DPDK package as what the verbs provider does.
AC_DEFUN([FI_DPDK_CONFIGURE],[
	# Determine if we can support the dpdk provider
    dpdk_happy=0
    AS_IF([test x"$enable_dpdk" != x"no"],[dpdk_happy=1])
       AS_IF([test $dpdk_happy -eq 1], [$1], [$2])

    # Set the default location of DPDK installation
    DPDK_DIR="/usr/local"
    DPDK_INCLUDE_DIR="$DPDK_DIR/include"
    DPDK_LIB_DIR="$DPDK_DIR/lib/x86_64-linux-gnu"

    # Check if DPDK is installed there
    AC_CHECK_FILE([$DPDK_INCLUDE_DIR/rte_config.h], [], [AC_MSG_ERROR([Cannot find DPDK header files])])
    AC_CHECK_FILE([$DPDK_LIB_DIR/librte_eal.so], [], [AC_MSG_ERROR([Cannot find DPDK libraries])])

    # Set the flags for DPDK
    dpdk_CPPFLAGS="-include rte_config.h -march=native -I$DPDK_INCLUDE_DIR -I/usr/include/libnl3"
    dpdk_CFLAGS="-include rte_config.h -march=native -I$DPDK_INCLUDE_DIR -I/usr/include/libnl3"
    dpdk_LDFLAGS="-L$DPDK_LIB_DIR"
    dpdk_LIBS="-L$DPDK_LIB_DIR -Wl,--as-needed -lrte_node -lrte_graph -lrte_flow_classify -lrte_pipeline -lrte_table -lrte_pdump -lrte_port -lrte_fib -lrte_ipsec -lrte_vhost -lrte_stack -lrte_security -lrte_sched -lrte_reorder -lrte_rib -lrte_dmadev -lrte_regexdev -lrte_rawdev -lrte_power -lrte_pcapng -lrte_member -lrte_lpm -lrte_latencystats -lrte_kni -lrte_jobstats -lrte_ip_frag -lrte_gso -lrte_gro -lrte_gpudev -lrte_eventdev -lrte_efd -lrte_distributor -lrte_cryptodev -lrte_compressdev -lrte_cfgfile -lrte_bpf -lrte_bitratestats -lrte_bbdev -lrte_acl -lrte_timer -lrte_hash -lrte_metrics -lrte_cmdline -lrte_pci -lrte_ethdev -lrte_meter -lrte_net -lrte_mbuf -lrte_mempool -lrte_rcu -lrte_ring -lrte_eal -lrte_telemetry -lrte_kvargs"

  	AC_SUBST(dpdk_CPPFLAGS)
	AC_SUBST(dpdk_LDFLAGS)
	AC_SUBST(dpdk_LIBS)
])
