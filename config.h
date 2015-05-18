/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.in by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Enable plugin support */
#define ENABLE_PLUGINS 1

/* ether_header uses ether_addr structs */
/* #undef ETHER_HEADER_HAS_EA */

/* ARM is supported */
/* #undef HAVE_ARM */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#define HAVE_ARPA_NAMESER_H 1

/* Define 1 if your version of gcc supports __sync_add_and_fetch */
#define HAVE_BUILTIN_ATOMIC 1

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <dl.h> header file. */
/* #undef HAVE_DL_H */

/* dna headers are present */
/* #undef HAVE_DNA_HEADERS */

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <ethertype.h> header file. */
/* #undef HAVE_ETHERTYPE_H */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* GeoIP support is present */
#define HAVE_GEOIP 1

/* Define to 1 if you have the <GeoIP.h> header file. */
#define HAVE_GEOIP_H 1

/* GeoIP IPv6 support is present */
#define HAVE_GEOIP_IPv6 1

/* Define to 1 if you have the <if.h> header file. */
/* #undef HAVE_IF_H */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `cyassl' library (-lcyassl). */
/* #undef HAVE_LIBCYASSL */

/* Define to 1 if you have the `dl' library (-ldl). */
#define HAVE_LIBDL 1

/* libevent is present */
#define HAVE_LIBEVENT 1

/* Define to 1 if you have the `GeoIP' library (-lGeoIP). */
#define HAVE_LIBGEOIP 1

/* Define to 1 if you have the `hiredis' library (-lhiredis). */
#define HAVE_LIBHIREDIS 1

/* Define to 1 if you have the `json-c' library (-ljson-c). */
#define HAVE_LIBJSON_C 1

/* Define to 1 if you have the `netfilter_queue' library (-lnetfilter_queue).
   */
/* #undef HAVE_LIBNETFILTER_QUEUE */

/* Define to 1 if you have the <libnetfilter_queue/libnetfilter_queue.h>
   header file. */
/* #undef HAVE_LIBNETFILTER_QUEUE_LIBNETFILTER_QUEUE_H */

/* libnuma is installed */
/* #undef HAVE_LIBNUMA */

/* Define to 1 if you have the `pcap' library (-lpcap). */
/* #undef HAVE_LIBPCAP */

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* Define to 1 if you have the `rdi' library (-lrdi). */
/* #undef HAVE_LIBRDI */

/* Define to 1 if you have the `resolv' library (-lresolv). */
#define HAVE_LIBRESOLV 1

/* Define to 1 if you have the `rt' library (-lrt). */
/* #undef HAVE_LIBRT */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the `zmq' library (-lzmq). */
#define HAVE_LIBZMQ 1

/* Check lprobe license */
#define HAVE_LICENSE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* use mysql */
/* #undef HAVE_MYSQL */

/* Define to 1 if you have the <mysql.h> header file. */
/* #undef HAVE_MYSQL_H */

/* Define to 1 if you have the <mysql/mysql.h> header file. */
/* #undef HAVE_MYSQL_MYSQL_H */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* NFQ is present */
/* #undef HAVE_NETFILTER */

/* Define to 1 if you have the <netinet/if_ether.h> header file. */
#define HAVE_NETINET_IF_ETHER_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/in_systm.h> header file. */
#define HAVE_NETINET_IN_SYSTM_H 1

/* Define to 1 if you have the <netinet/ip.h> header file. */
#define HAVE_NETINET_IP_H 1

/* Define to 1 if you have the <netinet/ip_icmp.h> header file. */
/* #undef HAVE_NETINET_IP_ICMP_H */

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#define HAVE_NETINET_TCP_H 1

/* Define to 1 if you have the <netinet/udp.h> header file. */
#define HAVE_NETINET_UDP_H 1

/* Define to 1 if you have the <net/bpf.h> header file. */
#define HAVE_NET_BPF_H 1

/* Define to 1 if you have the <net/ethernet.h> header file. */
#define HAVE_NET_ETHERNET_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* Time we compiled lprobe */
#define HAVE_NOW 1394119422

/* lprobe extensions present */
#define HAVE_lprobe_EXTENSIONS 1

/* libc has optreset */
#define HAVE_OPTRESET 1

/* pcap has pcap_next_ex */
#define HAVE_PCAP_NEXT_EX 1

/* Native PF_RING support */
/* #undef HAVE_PF_RING */

/* Check lprobe plugin licenses */
#define HAVE_PLUGIN_LICENSE 1

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* libpthread has pthread_setaffinity_np */
/* #undef HAVE_PTHREAD_SET_AFFINITY */

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Apache Kafka is present */
#define HAVE_RDKAFKA 1

/* redis is present */
#define HAVE_REDIS 1

/* pthread has rw locks */
#define HAVE_RW_LOCK 1

/* Define to 1 if you have the <sched.h> header file. */
#define HAVE_SCHED_H 1

/* SCTP is supported */
/* #undef HAVE_SCTP */

/* Define to 1 if you have the <semaphore.h> header file. */
#define HAVE_SEMAPHORE_H 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* sockaddr_in6 has sin6_len */
#define HAVE_SIN6_LEN 1

/* We have sqlite */
#define HAVE_SQLITE 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/ioctl> header file. */
/* #undef HAVE_SYS_IOCTL */

/* Define to 1 if you have the <sys/ldr.h> header file. */
/* #undef HAVE_SYS_LDR_H */

/* Define to 1 if you have the <sys/sched.h> header file. */
/* #undef HAVE_SYS_SCHED_H */

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
#define HAVE_SYS_SOCKIO_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syslog.h> header file. */
#define HAVE_SYS_SYSLOG_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Have template extensions */
/* #undef HAVE_TEMPLATE_EXTENSIONS */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* use yaSSL */
/* #undef HAVE_YASSL */

/* ZMQ is present */
#define HAVE_ZMQ 1

/* inet_aton */
/* #undef NEED_INET_ATON */

/* build for big endian */
/* #undef lprobe_BIG_ENDIAN */

/* build for little endian */
#define lprobe_LITTLE_ENDIAN 1

/* Name of package */
#define PACKAGE ""

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "lprobe"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "lprobe 6.16.140306"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "lprobe"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "6.16.140306"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION ""

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to `short' if <sys/types.h> does not define. */
/* #undef int16_t */

/* Define to `long' if <sys/types.h> does not define. */
/* #undef int32_t */

/* Define to `long long' if <sys/types.h> does not define. */
/* #undef int64_t */

/* Define to `char' if <sys/types.h> does not define. */
/* #undef int8_t */

/* Define to `unsigned short' if <sys/types.h> does not define. */
/* #undef u_int16_t */

/* Define to `unsigned long' if <sys/types.h> does not define. */
/* #undef u_int32_t */

/* Define to `unsigned long long' if <sys/types.h> does not define. */
/* #undef u_int64_t */

/* Define to `unsigned char' if <sys/types.h> does not define. */
/* #undef u_int8_t */
