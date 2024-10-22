
#include <config.h>

#include "netdev-sonic.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <math.h>
#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/virtio_net.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netlink.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "netdev-afxdp.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "netnsid.h"
#include "openvswitch/ofpbuf.h"
#include "openflow/openflow.h"
#include "ovs-atomic.h"
#include "ovs-numa.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "rtnetlink.h"
#include "openvswitch/shash.h"
#include "socket-util.h"
#include "sset.h"
#include "tc.h"
#include "timer.h"
#include "unaligned.h"
#include "openvswitch/vlog.h"
#include "userspace-tso.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netdev_sonic);

/*
COVERAGE_DEFINE(netdev_arp_lookup);
COVERAGE_DEFINE(netdev_get_ifindex);
COVERAGE_DEFINE(netdev_get_hwaddr);
COVERAGE_DEFINE(netdev_set_hwaddr);
COVERAGE_DEFINE(netdev_get_ethtool);
COVERAGE_DEFINE(netdev_set_ethtool);
*/

/* Linux 2.6.27 introduced ethtool_cmd_speed
 *
 * To avoid revisiting problems reported with using configure to detect
 * compatibility (see report at
 * https://mail.openvswitch.org/pipermail/ovs-dev/2014-October/291521.html)
 * unconditionally replace ethtool_cmd_speed. */
#define ethtool_cmd_speed rpl_ethtool_cmd_speed
static inline uint32_t rpl_ethtool_cmd_speed(const struct ethtool_cmd *ep)
{
        return ep->speed | (ep->speed_hi << 16);
}

/* Linux 2.6.30 introduced supported and advertised flags for
 * 1G base KX, and 10G base KX4, KR and R. */
#ifndef SUPPORTED_1000baseKX_Full
#define SUPPORTED_1000baseKX_Full      (1 << 17)
#define SUPPORTED_10000baseKX4_Full    (1 << 18)
#define SUPPORTED_10000baseKR_Full     (1 << 19)
#define SUPPORTED_10000baseR_FEC       (1 << 20)
#define ADVERTISED_1000baseKX_Full     (1 << 17)
#define ADVERTISED_10000baseKX4_Full   (1 << 18)
#define ADVERTISED_10000baseKR_Full    (1 << 19)
#define ADVERTISED_10000baseR_FEC      (1 << 20)
#endif

/* Linux 3.5 introduced supported and advertised flags for
 * 40G base KR4, CR4, SR4 and LR4. */
#ifndef SUPPORTED_40000baseKR4_Full
#define SUPPORTED_40000baseKR4_Full    (1 << 23)
#define SUPPORTED_40000baseCR4_Full    (1 << 24)
#define SUPPORTED_40000baseSR4_Full    (1 << 25)
#define SUPPORTED_40000baseLR4_Full    (1 << 26)
#define ADVERTISED_40000baseKR4_Full   (1 << 23)
#define ADVERTISED_40000baseCR4_Full   (1 << 24)
#define ADVERTISED_40000baseSR4_Full   (1 << 25)
#define ADVERTISED_40000baseLR4_Full   (1 << 26)
#endif


/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);


static void netdev_sonic_wait(const struct netdev_class *netdev_class OVS_UNUSED);
static struct netdev *netdev_sonic_alloc(void);
static void netdev_sonic_dealloc(struct netdev *netdev_);
static int netdev_sonic_construct(struct netdev *netdev_);
static void netdev_sonic_destruct(struct netdev *netdev_);
static int netdev_sonic_send(struct netdev *netdev_, int qid OVS_UNUSED,
                  struct dp_packet_batch *batch, bool concurrent_txq OVS_UNUSED);
static void netdev_sonic_send_wait(struct netdev *netdev, int qid OVS_UNUSED);
static int netdev_sonic_set_etheraddr(struct netdev *netdev_, const struct eth_addr mac);
static int netdev_sonic_get_etheraddr(const struct netdev *netdev_, struct eth_addr *mac);
static int netdev_sonic_get_mtu(const struct netdev *netdev_, int *mtup);
static int netdev_sonic_set_mtu(struct netdev *netdev_, int mtu);
static int netdev_sonic_get_ifindex(const struct netdev *netdev_);
static int netdev_sonic_get_carrier(const struct netdev *netdev_, bool *carrier);
static long long int netdev_sonic_get_carrier_resets(const struct netdev *netdev_);
static int netdev_sonic_set_miimon_interval(struct netdev *netdev_, long long int interval);
static int netdev_sonic_get_stats(const struct netdev *netdev_, struct netdev_stats *stats);
static int netdev_sonic_get_features(const struct netdev *netdev_,
                          enum netdev_features *current,
                          enum netdev_features *advertised,
                          enum netdev_features *supported,
                          enum netdev_features *peer);
static int netdev_sonic_set_advertisements(struct netdev *netdev_, enum netdev_features advertise);
static int netdev_sonic_set_policing(struct netdev *netdev_, uint32_t kbits_rate,
                          uint32_t kbits_burst, uint32_t kpkts_rate, uint32_t kpkts_burst);
static int netdev_sonic_get_qos_types(const struct netdev *netdev OVS_UNUSED, struct sset *types);
static int netdev_sonic_get_qos_capabilities(const struct netdev *netdev OVS_UNUSED,
                                  const char *type, struct netdev_qos_capabilities *caps);
static int netdev_sonic_get_qos(const struct netdev *netdev_, const char **typep, struct smap *details);
static int netdev_sonic_set_qos(struct netdev *netdev_, const char *type, const struct smap *details);
static int netdev_sonic_get_queue(const struct netdev *netdev_, unsigned int queue_id, struct smap *details);
static int netdev_sonic_set_queue(struct netdev *netdev_, unsigned int queue_id, const struct smap *details);
static int netdev_sonic_delete_queue(struct netdev *netdev_, unsigned int queue_id);
static int netdev_sonic_get_queue_stats(const struct netdev *netdev_,
                             unsigned int queue_id, struct netdev_queue_stats *stats);
static int netdev_sonic_queue_dump_start(const struct netdev *netdev_, void **statep);
static int netdev_sonic_queue_dump_next(const struct netdev *netdev_,
        void *state_, unsigned int *queue_idp, struct smap *details);
static int netdev_sonic_queue_dump_done(const struct netdev *netdev OVS_UNUSED, void *state_);
static int netdev_sonic_dump_queue_stats(const struct netdev *netdev_, netdev_dump_queue_stats_cb *cb, void *aux);
static int netdev_sonic_set_in4(struct netdev *netdev_, struct in_addr address, struct in_addr netmask);
static int netdev_sonic_get_addr_list(const struct netdev *netdev_,
                          struct in6_addr **addr, struct in6_addr **mask, int *n_cnt);
static int netdev_sonic_add_router(struct netdev *netdev OVS_UNUSED, struct in_addr router);
static int netdev_sonic_get_next_hop(const struct in_addr *host, struct in_addr *next_hop, char **netdev_name);
static int netdev_sonic_get_status(const struct netdev *netdev_, struct smap *smap);
static int netdev_sonic_arp_lookup(const struct netdev *netdev, ovs_be32 ip, struct eth_addr *mac);
static int netdev_sonic_update_flags(struct netdev *netdev_, enum netdev_flags off,
                          enum netdev_flags on, enum netdev_flags *old_flagsp);
static struct netdev_rxq *netdev_sonic_rxq_alloc(void);
static int netdev_sonic_rxq_construct(struct netdev_rxq *rxq_);
static void netdev_sonic_rxq_destruct(struct netdev_rxq *rxq_);
static void netdev_sonic_rxq_dealloc(struct netdev_rxq *rxq_);
static int netdev_sonic_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet_batch *batch, int *qfill);
static void netdev_sonic_rxq_wait(struct netdev_rxq *rxq_);
static int netdev_sonic_rxq_drain(struct netdev_rxq *rxq_);

static int get_etheraddr(const char *netdev_name, struct eth_addr *ea);
static int get_ethmtu(struct netdev_sonic *netdev, int *mtup);
static int get_ifindex(const struct netdev *netdev_, int *ifindexp);
static void read_features(struct netdev_sonic *netdev);
static int do_ethtool(const char *name, struct ethtool_cmd *ecmd, int cmd, const char *cmd_name);


/***** FAKE *****/
static int getFakePortIfindex(const char *netdev_name);
/***** FAKE END *****/




const struct netdev_class netdev_sonic_class = {
    .type = "sonic",
    .is_pmd = false,
    //.init
    .run = netdev_sonic_run,
    .wait = netdev_sonic_wait,
    .alloc = netdev_sonic_alloc,
    .construct = netdev_sonic_construct,
    .destruct = netdev_sonic_destruct,
    .dealloc = netdev_sonic_dealloc,
    .send = netdev_sonic_send,
    .send_wait = netdev_sonic_send_wait,
    .set_etheraddr = netdev_sonic_set_etheraddr,
    .get_etheraddr = netdev_sonic_get_etheraddr,
    .get_mtu = netdev_sonic_get_mtu,
    .set_mtu = netdev_sonic_set_mtu,
    .get_ifindex = netdev_sonic_get_ifindex,
    .get_carrier = netdev_sonic_get_carrier,
    .get_carrier_resets = netdev_sonic_get_carrier_resets,
    .set_miimon_interval = netdev_sonic_set_miimon_interval,
    .get_stats = netdev_sonic_get_stats,
    .get_features = netdev_sonic_get_features,
    .set_advertisements = netdev_sonic_set_advertisements,
    .set_policing = netdev_sonic_set_policing,
    .get_qos_types = netdev_sonic_get_qos_types,
    .get_qos_capabilities = netdev_sonic_get_qos_capabilities,
    .get_qos = netdev_sonic_get_qos,
    .set_qos = netdev_sonic_set_qos,
    .get_queue = netdev_sonic_get_queue,
    .set_queue = netdev_sonic_set_queue,
    .delete_queue = netdev_sonic_delete_queue,
    .get_queue_stats = netdev_sonic_get_queue_stats,
    .queue_dump_start = netdev_sonic_queue_dump_start,
    .queue_dump_next = netdev_sonic_queue_dump_next,
    .queue_dump_done = netdev_sonic_queue_dump_done,
    .dump_queue_stats = netdev_sonic_dump_queue_stats,
    .set_in4 = netdev_sonic_set_in4,
    .get_addr_list = netdev_sonic_get_addr_list,
    .add_router = netdev_sonic_add_router,
    .get_next_hop = netdev_sonic_get_next_hop,
    .get_status = netdev_sonic_get_status,
    .arp_lookup = netdev_sonic_arp_lookup,
    .update_flags = netdev_sonic_update_flags,
    .rxq_alloc = netdev_sonic_rxq_alloc,
    .rxq_construct = netdev_sonic_rxq_construct,
    .rxq_destruct = netdev_sonic_rxq_destruct,
    .rxq_dealloc = netdev_sonic_rxq_dealloc,
    .rxq_recv = netdev_sonic_rxq_recv,
    .rxq_wait = netdev_sonic_rxq_wait,
    .rxq_drain = netdev_sonic_rxq_drain
};

/* fake port database; real port should from linux ethtool ???
 */
static netdev_sonic_port_t port_ar[NETDEV_SONIC_PORT_MAX_COUNT]; //fake port size


void
netdev_sonic_run(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

const char *
netdev_sonic_get_dpif_port(const struct netdev *netdev,
                           char namebuf[], size_t bufsize)
{
    return netdev->name;
}

void netdev_sonic_port_init(void)
{
    memset(port_ar, 0, sizeof(port_ar));
}

int netdev_sonic_port_add(const char *port_name_p, int *port_no)
{
    int ifindex = 0;

    if (strlen(port_name_p) >= NETDEV_SONIC_PORT_MAX_NAME_LEN) {
        VLOG_ERR("%s %d. port_name_p:%s exceed max length", __FUNCTION__, __LINE__, port_name_p);
        return EOPNOTSUPP;
    }

    if (strstr(port_name_p, "Ethernet") != NULL) {
        char port_no_ar[4] = {0};
        sscanf(port_name_p, "Ethernet%[0-9]", port_no_ar);
        ifindex = atoi(port_no_ar);
    } else {
        ifindex = (NETDEV_SONIC_PORT_MAX_COUNT - 1);
    }

    if (NETDEV_SONIC_PORT_MAX_COUNT <= ifindex) {
        VLOG_ERR("%s %d. ifindex:%d exceed max ifindex", __FUNCTION__, __LINE__, ifindex);
        return EOPNOTSUPP;
    }

    strcpy(port_ar[ifindex].name_ar, port_name_p);
    port_ar[ifindex].ifindex = ifindex;
    port_ar[ifindex].active = 1;
    *port_no = ifindex;

    return 0;
}

int netdev_sonic_port_del(int port_no)
{
    if (NETDEV_SONIC_PORT_MAX_COUNT <= port_no) {
        VLOG_ERR("%s %d. invalid port_no:%d.", __FUNCTION__, __LINE__, port_no);
        return EOPNOTSUPP;
    }

    if (0 != port_ar[port_no].active) {
        memset(&port_ar[port_no], 0, sizeof(port_ar[port_no]));
    }
    return 0;
}

int netdev_sonic_port_query_by_number(int port_no, netdev_sonic_port_t *data_p)
{
    if (0 != port_ar[port_no].active) {
        strcpy(data_p->name_ar, port_ar[port_no].name_ar);
        data_p->ifindex = port_ar[port_no].ifindex;
        return 0;
    }

    return ENODEV;
}

int netdev_sonic_port_query_by_name(const char *port_name_p, netdev_sonic_port_t *data_p)
{
    int idx = 0;

    for (idx = 0; idx < NETDEV_SONIC_PORT_MAX_COUNT; idx++) {
        if (0 == strcmp(port_name_p, port_ar[idx].name_ar)) {
            strcpy(data_p->name_ar, port_ar[idx].name_ar);
            data_p->ifindex = port_ar[idx].ifindex;
            return 0;
        }
    }
    return ENODEV;
}

int netdev_sonic_port_next(netdev_sonic_port_t *data_p)
{
    int ifindex = 0;
    int idx = 0;

    if (0 != strlen(data_p->name_ar)) { //NOT get initial
        ifindex = (data_p->ifindex + 1);
    }

    for (idx = ifindex; idx < NETDEV_SONIC_PORT_MAX_COUNT; idx++) {
        if (0 != port_ar[idx].active) {
            strcpy(data_p->name_ar, port_ar[idx].name_ar);
            data_p->ifindex = port_ar[idx].ifindex;
            return 0;
        }
    }
    return EOF;
}


static void
netdev_sonic_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

static struct netdev *
netdev_sonic_alloc(void)
{
    struct netdev_sonic *netdev = xzalloc(sizeof *netdev);

    return &netdev->up;
}

static void
netdev_sonic_dealloc(struct netdev *netdev_)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);

    free(netdev);
}

static int
netdev_sonic_construct(struct netdev *netdev_)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);
    const char *name = netdev_->name;

    ovs_mutex_init(&netdev->mutex);
    return 0;
}

static void
netdev_sonic_destruct(struct netdev *netdev_)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);

    ovs_mutex_destroy(&netdev->mutex);
}

static int
netdev_sonic_send(struct netdev *netdev_, int qid OVS_UNUSED,
                  struct dp_packet_batch *batch,
                  bool concurrent_txq OVS_UNUSED)
{

    return 0;
}

static void
netdev_sonic_send_wait(struct netdev *netdev, int qid OVS_UNUSED)
{

}

static int
netdev_sonic_set_etheraddr(struct netdev *netdev_, const struct eth_addr mac)
{
    /* should not set this
     */

    return 0;
}

static int
netdev_sonic_get_etheraddr(const struct netdev *netdev_, struct eth_addr *mac)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    netdev->ether_addr_error = get_etheraddr(netdev_get_name(netdev_),
                                             &netdev->etheraddr);
    ovs_mutex_unlock(&netdev->mutex);
    return netdev->ether_addr_error;;
}

static int
netdev_sonic_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    error = get_ethmtu(netdev, mtup);
    ovs_mutex_unlock(&netdev->mutex);
    return error;
}

static int
netdev_sonic_set_mtu(struct netdev *netdev_, int mtu)
{
    //struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);

    //ovs_mutex_lock(&netdev->mutex);

    //ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_sonic_get_ifindex(const struct netdev *netdev_)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);
    int ifindex, error;

    ovs_mutex_lock(&netdev->mutex);
    error = get_ifindex(netdev_, &ifindex);

    if (ifindex < 0) {
        netdev->get_ifindex_error = -ifindex;
        netdev->ifindex = 0;
    } else {
        netdev->get_ifindex_error = 0;
        netdev->ifindex = ifindex;
    }
    ovs_mutex_unlock(&netdev->mutex);
    return (ifindex < 0) ? -1 : ifindex;  //return minus value when failed
}

static int
netdev_sonic_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    //struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);

    //ovs_mutex_lock(&netdev->mutex);

    //ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static long long int
netdev_sonic_get_carrier_resets(const struct netdev *netdev_)
{
    //struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);

    //ovs_mutex_lock(&netdev->mutex);

    //ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_sonic_set_miimon_interval(struct netdev *netdev_,
                                 long long int interval)
{

    return 0;
}

static int
netdev_sonic_get_stats(const struct netdev *netdev_,
                       struct netdev_stats *stats)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);
    struct netdev_stats dev_stats;
    int error;

    ovs_mutex_lock(&netdev->mutex);
    memset(stats, 0, sizeof(struct netdev_stats));
    /* get stats from dp ???
     */


    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

/* Stores the features supported by 'netdev' into of '*current', '*advertised',
 * '*supported', and '*peer'.  Each value is a bitmap of NETDEV_* bits.
 * Returns 0 if successful, otherwise a positive errno value. */
static int
netdev_sonic_get_features(const struct netdev *netdev_,
                          enum netdev_features *current,
                          enum netdev_features *advertised,
                          enum netdev_features *supported,
                          enum netdev_features *peer)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);

    read_features(netdev);

    if (!netdev->get_features_error) {
        *current = netdev->current;
        *advertised = netdev->advertised;
        *supported = netdev->supported;
        *peer = 0;              /* XXX */
    }
    error = netdev->get_features_error;

    ovs_mutex_unlock(&netdev->mutex);
    return error;
}

static int
netdev_sonic_set_advertisements(struct netdev *netdev_,
                                enum netdev_features advertise)
{
    //should set by sonic cmd, not ovs

    return 0;
}

static int
netdev_sonic_set_policing(struct netdev *netdev_, uint32_t kbits_rate,
                          uint32_t kbits_burst, uint32_t kpkts_rate,
                          uint32_t kpkts_burst)
{
    //should set by sonic cmd, not ovs

    return 0;
}

static int
netdev_sonic_get_qos_types(const struct netdev *netdev OVS_UNUSED,
                           struct sset *types)
{

    sset_add(types, "linux-htb"); /* fake ??? */
    return 0;
}

static int
netdev_sonic_get_qos_capabilities(const struct netdev *netdev OVS_UNUSED,
                                  const char *type,
                                  struct netdev_qos_capabilities *caps)
{

    caps->n_queues = 8; /* fake ??? */
    return 0;
}

static int
netdev_sonic_get_qos(const struct netdev *netdev_,
                     const char **typep, struct smap *details)
{

    return 0;
}

static int
netdev_sonic_set_qos(struct netdev *netdev_,
                     const char *type, const struct smap *details)
{

    return 0;
}

static int
netdev_sonic_get_queue(const struct netdev *netdev_,
                       unsigned int queue_id, struct smap *details)
{

    return 0;
}

static int
netdev_sonic_set_queue(struct netdev *netdev_,
                       unsigned int queue_id, const struct smap *details)
{

    return 0;
}

static int
netdev_sonic_delete_queue(struct netdev *netdev_, unsigned int queue_id)
{

    return 0;
}

static int
netdev_sonic_get_queue_stats(const struct netdev *netdev_,
                             unsigned int queue_id,
                             struct netdev_queue_stats *stats)
{

    return 0;
}

static int
netdev_sonic_queue_dump_start(const struct netdev *netdev_, void **statep)
{

    //*statep = state = xmalloc(sizeof *state);
    //state->queues = xmalloc(state->n_queues * sizeof *state->queues);
    return 0;
}

static int
netdev_sonic_queue_dump_next(const struct netdev *netdev_, void *state_,
                             unsigned int *queue_idp, struct smap *details)
{
    int error = EOF;

    return 0;
}

static int
netdev_sonic_queue_dump_done(const struct netdev *netdev OVS_UNUSED,
                             void *state_)
{

    //free(state->queues); allocate by netdev_sonic_queue_dump_start
    //free(state);
    return 0;
}

static int
netdev_sonic_dump_queue_stats(const struct netdev *netdev_,
                              netdev_dump_queue_stats_cb *cb, void *aux)
{

    return 0;
}

static int
netdev_sonic_set_in4(struct netdev *netdev_, struct in_addr address,
                     struct in_addr netmask)
{

    return 0;
}

static int
netdev_sonic_get_addr_list(const struct netdev *netdev_,
                          struct in6_addr **addr, struct in6_addr **mask, int *n_cnt)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    error = netdev_get_addrs(netdev_get_name(netdev_), addr, mask, n_cnt);
    ovs_mutex_unlock(&netdev->mutex);
    return error;
}

static int
netdev_sonic_add_router(struct netdev *netdev OVS_UNUSED, struct in_addr router)
{

    return 0;
}

static int
netdev_sonic_get_next_hop(const struct in_addr *host, struct in_addr *next_hop,
                          char **netdev_name)
{
    static const char fn[] = "/proc/net/route";
    FILE *stream;
    char line[256];
    int ln;


    *netdev_name = NULL;
    stream = fopen(fn, "r");
    if (stream == NULL) {
        VLOG_WARN_RL(&rl, "%s: open failed: %s", fn, ovs_strerror(errno));
        return errno;
    }

    ln = 0;
    while (fgets(line, sizeof line, stream)) {
        if (++ln >= 2) {
            char iface[17];
            ovs_be32 dest, gateway, mask;
            int refcnt, metric, mtu;
            unsigned int flags, use, window, irtt;

            if (!ovs_scan(line,
                          "%16s %"SCNx32" %"SCNx32" %04X %d %u %d %"SCNx32
                          " %d %u %u\n",
                          iface, &dest, &gateway, &flags, &refcnt,
                          &use, &metric, &mask, &mtu, &window, &irtt)) {
                VLOG_WARN_RL(&rl, "%s: could not parse line %d: %s",
                        fn, ln, line);
                continue;
            }
            if (!(flags & RTF_UP)) {
                /* Skip routes that aren't up. */
                continue;
            }

            /* The output of 'dest', 'mask', and 'gateway' were given in
             * network byte order, so we don't need need any endian
             * conversions here. */
            if ((dest & mask) == (host->s_addr & mask)) {
                if (!gateway) {
                    /* The host is directly reachable. */
                    next_hop->s_addr = 0;
                } else {
                    /* To reach the host, we must go through a gateway. */
                    next_hop->s_addr = gateway;
                }
                *netdev_name = xstrdup(iface);
                fclose(stream);
                return 0;
            }
        }
    }

    fclose(stream);
    return ENXIO;
}

static int
netdev_sonic_get_status(const struct netdev *netdev_, struct smap *smap)
{
    struct netdev_sonic *netdev = netdev_sonic_cast(netdev_);
    int error = 0;
    VLOG_INFO("%s %d.", __FUNCTION__, __LINE__);

/***** FAKE *****/
    char *netdev_name = netdev_get_name(netdev);
    int ifindex = getFakePortIfindex(netdev_name);
    VLOG_INFO("%s %d. netdev_name:%s.", __FUNCTION__, __LINE__, netdev_name);
    if (0 >= ifindex) {
        smap_add(smap, "driver_name", netdev_name);
        smap_add(smap, "driver_version", "unknown");
        smap_add(smap, "firmware_version", "unknown");
        return 0;
    }
/***** FAKE END *****/

    ovs_mutex_lock(&netdev->mutex);

    struct ethtool_cmd *cmd = (struct ethtool_cmd *) &netdev->drvinfo;
    //COVERAGE_INC(netdev_get_ethtool);
    memset(&netdev->drvinfo, 0, sizeof netdev->drvinfo);
    error = do_ethtool(netdev->up.name, cmd, ETHTOOL_GDRVINFO, "ETHTOOL_GDRVINFO");

    if (!error) {
        smap_add(smap, "driver_name", netdev->drvinfo.driver);
        smap_add(smap, "driver_version", netdev->drvinfo.version);
        smap_add(smap, "firmware_version", netdev->drvinfo.fw_version);
    }
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_sonic_arp_lookup(const struct netdev *netdev,
                        ovs_be32 ip, struct eth_addr *mac)
{
    struct arpreq r;
    struct sockaddr_in sin;
    int retval;

    VLOG_INFO("%s %d.", __FUNCTION__, __LINE__);
    memset(&r, 0, sizeof r);
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = 0;
    memcpy(&r.arp_pa, &sin, sizeof sin);
    r.arp_ha.sa_family = ARPHRD_ETHER;
    r.arp_flags = 0;
    ovs_strzcpy(r.arp_dev, netdev_get_name(netdev), sizeof r.arp_dev);
    //COVERAGE_INC(netdev_arp_lookup);
    retval = af_inet_ioctl(SIOCGARP, &r);
    if (!retval) {
        memcpy(mac, r.arp_ha.sa_data, ETH_ADDR_LEN);
    } else if (retval != ENXIO) {
        VLOG_WARN_RL(&rl, "%s: could not look up ARP entry for "IP_FMT": %s",
                     netdev_get_name(netdev), IP_ARGS(ip),
                     ovs_strerror(retval));
    }
    return retval;
}

static int
netdev_sonic_update_flags(struct netdev *netdev_, enum netdev_flags off,
                          enum netdev_flags on, enum netdev_flags *old_flagsp)
{

    return 0;
}

static struct netdev_rxq *
netdev_sonic_rxq_alloc(void)
{

    struct netdev_rxq *rx = xzalloc(sizeof *rx);
    return &rx;
}

static int
netdev_sonic_rxq_construct(struct netdev_rxq *rxq_)
{

    return 0;
}

static void
netdev_sonic_rxq_destruct(struct netdev_rxq *rxq_)
{

}

static void
netdev_sonic_rxq_dealloc(struct netdev_rxq *rxq_)
{

    free(rxq_);
}

static int
netdev_sonic_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet_batch *batch,
                      int *qfill)
{

    return 0;
}

static void
netdev_sonic_rxq_wait(struct netdev_rxq *rxq_)
{

}

static int
netdev_sonic_rxq_drain(struct netdev_rxq *rxq_)
{

}






static int get_etheraddr(const char *netdev_name, struct eth_addr *ea)
{
    struct ifreq ifr;
    int hwaddr_family;
    int error;

/***** FAKE *****/
    int ifindex = getFakePortIfindex(netdev_name);
    VLOG_INFO("%s %d. netdev_name:%s.", __FUNCTION__, __LINE__, netdev_name);
    if (0 >= ifindex) {
        char mac_ar[ETH_ADDR_LEN] = {0};
        mac_ar[ETH_ADDR_LEN - 1] = ifindex;
        memcpy(ea, mac_ar, ETH_ADDR_LEN);
        return 0;
    }
/***** FAKE END *****/

    memset(&ifr, 0, sizeof ifr);
    ovs_strzcpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    //COVERAGE_INC(netdev_get_hwaddr);
    error = af_inet_ioctl(SIOCGIFHWADDR, &ifr);
    if (error) {
        /* ENODEV probably means that a vif disappeared asynchronously and
         * hasn't been removed from the database yet, so reduce the log level
         * to INFO for that case. */
        VLOG(error == ENODEV ? VLL_INFO : VLL_ERR,
             "ioctl(SIOCGIFHWADDR) on %s device failed: %s",
             netdev_name, ovs_strerror(error));
        return error;
    }
    hwaddr_family = ifr.ifr_hwaddr.sa_family;
    if (hwaddr_family != AF_UNSPEC && hwaddr_family != ARPHRD_ETHER &&
        hwaddr_family != ARPHRD_NONE) {
        VLOG_INFO("%s device has unknown hardware address family %d",
                  netdev_name, hwaddr_family);
        return EINVAL;
    }
    memcpy(ea, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);
    return 0;
}

static int get_ethmtu(struct netdev_sonic *netdev, int *mtup)
{
    char *netdev_name = netdev_get_name(netdev);
    int error;
    struct ifreq ifr;

/***** FAKE *****/
    int ifindex = getFakePortIfindex(netdev_name);
    VLOG_INFO("%s %d. netdev_name:%s.", __FUNCTION__, __LINE__, netdev_name);
    if (0 >= ifindex) {
        *mtup = 1500;
        return 0;
    }
/***** FAKE END *****/

    netdev->netdev_mtu_error = af_inet_ifreq_ioctl(
            netdev_get_name(&netdev->up), &ifr, SIOCGIFMTU, "SIOCGIFMTU");
    netdev->mtu = ifr.ifr_mtu;

    error = netdev->netdev_mtu_error;

    if (!error) {
        *mtup = netdev->mtu;
    }

    return error;
}

static int get_ifindex(const struct netdev *netdev_, int *ifindexp)
{
    char *netdev_name = netdev_get_name(netdev_);
    struct ifreq ifr;
    int error;

/***** FAKE *****/
    int ifindex = getFakePortIfindex(netdev_name);
    VLOG_INFO("%s %d. netdev_name:%s.", __FUNCTION__, __LINE__, netdev_name);
    if (0 >= ifindex) {
        *ifindexp = ifindex;
        return ifindex;
    }
/***** FAKE END *****/

    //fake test database ???
    int idx = 0;
    VLOG_INFO("%s %d. netdev_name:%s.", __FUNCTION__, __LINE__, netdev_name);
    for (idx = 0; idx < NETDEV_SONIC_PORT_MAX_COUNT; idx++)
    {
        if (0 == strcmp(netdev_name, port_ar[idx].name_ar))
        {
            *ifindexp = port_ar[idx].ifindex;
            return port_ar[idx].ifindex;
        }
    }

    ovs_strzcpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    //COVERAGE_INC(netdev_get_ifindex);

    error = af_inet_ioctl(SIOCGIFINDEX, &ifr);
    if (error) {
        /* ENODEV probably means that a vif disappeared asynchronously and
         * hasn't been removed from the database yet, so reduce the log level
         * to INFO for that case. */
        VLOG_RL(&rl, error == ENODEV ? VLL_INFO : VLL_ERR,
                "ioctl(SIOCGIFINDEX) on %s device failed: %s",
                netdev_name, ovs_strerror(error));
        return -error;
    }
    return ifr.ifr_ifindex;
}

static void read_features(struct netdev_sonic *netdev)
{
    char *netdev_name = netdev_get_name(netdev);
    struct ethtool_cmd ecmd;
    uint32_t speed;
    int error;

/***** FAKE *****/
    int ifindex = getFakePortIfindex(netdev_name);
    VLOG_INFO("%s %d. netdev_name:%s.", __FUNCTION__, __LINE__, netdev_name);
    if (0 >= ifindex) {
        netdev->supported |= NETDEV_F_1GB_HD;
        netdev->supported |= NETDEV_F_1GB_FD;
        netdev->supported |= NETDEV_F_FIBER;
        netdev->supported |= NETDEV_F_AUTONEG;
        netdev->advertised |= NETDEV_F_1GB_HD;
        netdev->advertised |= NETDEV_F_1GB_FD;
        netdev->advertised |= NETDEV_F_FIBER;
        netdev->advertised |= NETDEV_F_AUTONEG;
        netdev->current = NETDEV_F_1GB_FD;
        netdev->current |= NETDEV_F_FIBER;
        netdev->current |= NETDEV_F_AUTONEG;
        netdev->get_features_error = 0;
        return;
    }
/***** FAKE END *****/

    //COVERAGE_INC(netdev_get_ethtool);
    memset(&ecmd, 0, sizeof ecmd);
    error = do_ethtool(netdev->up.name, &ecmd, ETHTOOL_GSET, "ETHTOOL_GSET");
    if (error) {
        goto out;
    }

    /* Supported features. */
    netdev->supported = 0;
    if (ecmd.supported & SUPPORTED_10baseT_Half) {
        netdev->supported |= NETDEV_F_10MB_HD;
    }
    if (ecmd.supported & SUPPORTED_10baseT_Full) {
        netdev->supported |= NETDEV_F_10MB_FD;
    }
    if (ecmd.supported & SUPPORTED_100baseT_Half)  {
        netdev->supported |= NETDEV_F_100MB_HD;
    }
    if (ecmd.supported & SUPPORTED_100baseT_Full) {
        netdev->supported |= NETDEV_F_100MB_FD;
    }
    if (ecmd.supported & SUPPORTED_1000baseT_Half) {
        netdev->supported |= NETDEV_F_1GB_HD;
    }
    if ((ecmd.supported & SUPPORTED_1000baseT_Full) ||
        (ecmd.supported & SUPPORTED_1000baseKX_Full)) {
        netdev->supported |= NETDEV_F_1GB_FD;
    }
    if ((ecmd.supported & SUPPORTED_10000baseT_Full) ||
        (ecmd.supported & SUPPORTED_10000baseKX4_Full) ||
        (ecmd.supported & SUPPORTED_10000baseKR_Full) ||
        (ecmd.supported & SUPPORTED_10000baseR_FEC)) {
        netdev->supported |= NETDEV_F_10GB_FD;
    }
    if ((ecmd.supported & SUPPORTED_40000baseKR4_Full) ||
        (ecmd.supported & SUPPORTED_40000baseCR4_Full) ||
        (ecmd.supported & SUPPORTED_40000baseSR4_Full) ||
        (ecmd.supported & SUPPORTED_40000baseLR4_Full)) {
        netdev->supported |= NETDEV_F_40GB_FD;
    }
    if (ecmd.supported & SUPPORTED_TP) {
        netdev->supported |= NETDEV_F_COPPER;
    }
    if (ecmd.supported & SUPPORTED_FIBRE) {
        netdev->supported |= NETDEV_F_FIBER;
    }
    if (ecmd.supported & SUPPORTED_Autoneg) {
        netdev->supported |= NETDEV_F_AUTONEG;
    }
    if (ecmd.supported & SUPPORTED_Pause) {
        netdev->supported |= NETDEV_F_PAUSE;
    }
    if (ecmd.supported & SUPPORTED_Asym_Pause) {
        netdev->supported |= NETDEV_F_PAUSE_ASYM;
    }

    /* Advertised features. */
    netdev->advertised = 0;
    if (ecmd.advertising & ADVERTISED_10baseT_Half) {
        netdev->advertised |= NETDEV_F_10MB_HD;
    }
    if (ecmd.advertising & ADVERTISED_10baseT_Full) {
        netdev->advertised |= NETDEV_F_10MB_FD;
    }
    if (ecmd.advertising & ADVERTISED_100baseT_Half) {
        netdev->advertised |= NETDEV_F_100MB_HD;
    }
    if (ecmd.advertising & ADVERTISED_100baseT_Full) {
        netdev->advertised |= NETDEV_F_100MB_FD;
    }
    if (ecmd.advertising & ADVERTISED_1000baseT_Half) {
        netdev->advertised |= NETDEV_F_1GB_HD;
    }
    if ((ecmd.advertising & ADVERTISED_1000baseT_Full) ||
        (ecmd.advertising & ADVERTISED_1000baseKX_Full)) {
        netdev->advertised |= NETDEV_F_1GB_FD;
    }
    if ((ecmd.advertising & ADVERTISED_10000baseT_Full) ||
        (ecmd.advertising & ADVERTISED_10000baseKX4_Full) ||
        (ecmd.advertising & ADVERTISED_10000baseKR_Full) ||
        (ecmd.advertising & ADVERTISED_10000baseR_FEC)) {
        netdev->advertised |= NETDEV_F_10GB_FD;
    }
    if ((ecmd.advertising & ADVERTISED_40000baseKR4_Full) ||
        (ecmd.advertising & ADVERTISED_40000baseCR4_Full) ||
        (ecmd.advertising & ADVERTISED_40000baseSR4_Full) ||
        (ecmd.advertising & ADVERTISED_40000baseLR4_Full)) {
        netdev->advertised |= NETDEV_F_40GB_FD;
    }
    if (ecmd.advertising & ADVERTISED_TP) {
        netdev->advertised |= NETDEV_F_COPPER;
    }
    if (ecmd.advertising & ADVERTISED_FIBRE) {
        netdev->advertised |= NETDEV_F_FIBER;
    }
    if (ecmd.advertising & ADVERTISED_Autoneg) {
        netdev->advertised |= NETDEV_F_AUTONEG;
    }
    if (ecmd.advertising & ADVERTISED_Pause) {
        netdev->advertised |= NETDEV_F_PAUSE;
    }
    if (ecmd.advertising & ADVERTISED_Asym_Pause) {
        netdev->advertised |= NETDEV_F_PAUSE_ASYM;
    }

    /* Current settings. */
    speed = ethtool_cmd_speed(&ecmd);
    if (speed == SPEED_10) {
        netdev->current = ecmd.duplex ? NETDEV_F_10MB_FD : NETDEV_F_10MB_HD;
    } else if (speed == SPEED_100) {
        netdev->current = ecmd.duplex ? NETDEV_F_100MB_FD : NETDEV_F_100MB_HD;
    } else if (speed == SPEED_1000) {
        netdev->current = ecmd.duplex ? NETDEV_F_1GB_FD : NETDEV_F_1GB_HD;
    } else if (speed == SPEED_10000) {
        netdev->current = NETDEV_F_10GB_FD;
    } else if (speed == 40000) {
        netdev->current = NETDEV_F_40GB_FD;
    } else if (speed == 100000) {
        netdev->current = NETDEV_F_100GB_FD;
    } else if (speed == 1000000) {
        netdev->current = NETDEV_F_1TB_FD;
    } else {
        netdev->current = 0;
    }

    if (ecmd.port == PORT_TP) {
        netdev->current |= NETDEV_F_COPPER;
    } else if (ecmd.port == PORT_FIBRE) {
        netdev->current |= NETDEV_F_FIBER;
    }

    if (ecmd.autoneg) {
        netdev->current |= NETDEV_F_AUTONEG;
    }

out:
    netdev->get_features_error = error;
}

static int do_ethtool(const char *name, struct ethtool_cmd *ecmd,
                        int cmd, const char *cmd_name)
{
    struct ifreq ifr;
    int error;

    memset(&ifr, 0, sizeof ifr);
    ovs_strzcpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    ifr.ifr_data = (caddr_t) ecmd;

    ecmd->cmd = cmd;
    error = af_inet_ioctl(SIOCETHTOOL, &ifr);
    if (error) {
        if (error != EOPNOTSUPP) {
            VLOG_WARN_RL(&rl, "ethtool command %s on network device %s "
                         "failed: %s", cmd_name, name, ovs_strerror(error));
        } else {
            /* The device doesn't support this operation.  That's pretty
             * common, so there's no point in logging anything. */
        }
    }
    return error;
}


/***** FAKE *****/
static int getFakePortIfindex(const char *netdev_name) {
    int idx = 0;
    VLOG_INFO("%s %d. netdev_name:%s.", __FUNCTION__, __LINE__, netdev_name);
    for (idx = 0; idx < NETDEV_SONIC_PORT_MAX_COUNT; idx++)
    {
        if (0 == strcmp(netdev_name, port_ar[idx].name_ar))
        {
            return port_ar[idx].ifindex;
        }
    }
    return -1;
}
/***** FAKE END *****/
