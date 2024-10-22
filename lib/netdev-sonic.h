
#ifndef NETDEV_SONIC_H
#define NETDEV_SONIC_H 1

#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <stdint.h>
#include <stdbool.h>

#include "dp-packet.h"
#include "netdev-afxdp.h"
#include "netdev-afxdp-pool.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "openvswitch/thread.h"
#include "ovs-atomic.h"
#include "timer.h"


#define NETDEV_SONIC_PORT_MAX_COUNT 100
#define NETDEV_SONIC_PORT_MAX_NAME_LEN 12

struct netdev;


struct netdev_sonic {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    unsigned int cache_valid;

    int ifindex;
    struct eth_addr etheraddr;
    int mtu;

    uint32_t kbits_rate;        /* Policing data - kbps */
    uint32_t kbits_burst;
    uint32_t kpkts_rate;        /* Policing data - kpps */
    uint32_t kpkts_burst;

    int ether_addr_error;       /* Cached error code from set/get etheraddr. */
    int get_features_error;     /* Cached error code from ETHTOOL_GSET. */
    int get_ifindex_error;      /* Cached error code from SIOCGIFINDEX. */
    int netdev_mtu_error;       /* Cached error code from SIOCGIFMTU or SIOCSIFMTU. */

    enum netdev_features current;    /* Cached from ETHTOOL_GSET. */
    enum netdev_features advertised; /* Cached from ETHTOOL_GSET. */
    enum netdev_features supported;  /* Cached from ETHTOOL_GSET. */
    struct ethtool_drvinfo drvinfo;  /* Cached from ETHTOOL_GDRVINFO. */

    uint64_t tx_dropped;        /* tap device can drop if the iface is down */
    uint64_t rx_dropped;        /* Packets dropped while recv from kernel. */
};

typedef struct netdev_sonic_port {
    int ifindex;
    char name_ar[NETDEV_SONIC_PORT_MAX_NAME_LEN];  //port name
    int active; //used when 1; default 0
} netdev_sonic_port_t;

void netdev_sonic_run(const struct netdev_class *);

static bool
is_netdev_sonic_class(const struct netdev_class *netdev_class)
{
    return netdev_class->run == netdev_sonic_run;
}

static struct netdev_sonic *
netdev_sonic_cast(const struct netdev *netdev)
{
    ovs_assert(is_netdev_sonic_class(netdev_get_class(netdev)));

    return CONTAINER_OF(netdev, struct netdev_sonic, up);
}

const char *netdev_sonic_get_dpif_port(const struct netdev *,
                                       char namebuf[], size_t bufsize)
    OVS_WARN_UNUSED_RESULT;

void netdev_sonic_port_init(void);
int netdev_sonic_port_add(const char *port_name_p, int *port_no);
int netdev_sonic_port_del(int port_no);
int netdev_sonic_port_query_by_number(int port_no, netdev_sonic_port_t *data_p);
int netdev_sonic_port_query_by_name(const char *port_name_p, netdev_sonic_port_t *data_p);
int netdev_sonic_port_next(netdev_sonic_port_t *data_p);

#endif /* NETDEV_SONIC_H */
