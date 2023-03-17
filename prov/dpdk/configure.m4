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
m4_include([config/fi_pkg.m4])

AC_DEFUN([FI_DPDK_CONFIGURE],[
    # Determine if we can support the dpdk provider
    dpdk_happy=0
    AS_IF([test x"$enable_dpdk" != x"no"],[dpdk_happy=1])

    # Set the DPDK environments
    AS_IF([test $dpdk_happy -eq 1],
          [FI_PKG_CHECK_MODULES([dpdk], [libdpdk >= 22.11.0], [], [AC_MSG_ERROR([Cannot find libdpdk>=22.11.0, or pkg-config is not found.])])],
          [])

    # Set the flags for DPDK
    dpdk_CPPFLAGS=${dpdk_CFLAGS}

    AC_SUBST(dpdk_CFLAGS)
  	AC_SUBST(dpdk_CPPFLAGS)
	AC_SUBST(dpdk_LIBS)

    AS_IF([test $dpdk_happy -eq 1], [$1], [$2])
])
