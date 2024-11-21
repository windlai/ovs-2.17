
#include <config.h>

#include "dpif-sonic.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

#include "bitmap.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "netdev.h"
#include "netdev-sonic.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "odp-util.h"
#include "odp-netlink.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/flow.h"
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "openvswitch/thread.h"
#include "openvswitch/usdt-probes.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "random.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"


VLOG_DEFINE_THIS_MODULE(dpif_sonic);

#define FLOW_DUMP_MAX_BATCH 50

/* Set of supported meter flags */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Set of supported meter band types */
#define DP_SUPPORTED_METER_BAND_TYPES           \
    ( 1 << OFPMBT13_DROP )

#define MASK(PTR, FIELD) PTR ? &PTR->FIELD : NULL
#define OVS_KEY_ATTR_STR_SIZE 20

#define PORT_LOOP_GET_FIRST_IFINDEX_POSITION -1

#define INVALID_IFINDEX -1
#define REDIS_CMD_TYPE_REMOVE 0
#define REDIS_CMD_TYPE_ADD 1

#define REDIS_CMD_ACL_TABLE_NAME_LEN 32

/* define the max length of redis command
 * L3 add command, ex,
 * hset ACL_RULE|ACL_ETH999|65535 PRIORITY 65535 VLAN_ID 4094
 *      SRC_IP 192.168.111.100/32 DST_IP 192.168.111.101/32
 *      IP_PROTOCOL 255 L4_SRC_PORT 65535 L4_DST_PORT 65533 ETHER_TYPE 0x8892
 *      IP_TYPE IPV4ANY ICMP_CODE 255 ICMP_TYPE 233 REDIRECT_ACTION Ethernet999
 * L3v6 add command, ex,
 * hset ACL_RULE|ACL_ETH9996v6|65535 PRIORITY 65535 VLAN_ID 4094
 *      DST_IPV6 2001:0000:130F:0000:0000:09C0:876A:130B/128
 *      SRC_IPV6 2001:0000:130F:0000:0000:09C0:876A:130B/126
 *      ICMPV6_CODE 254 ICMPV6_TYPE 255 IP_TYPE IPV6ANY REDIRECT_ACTION Ethernet999
 */
#define REDIS_CMD_MAX_LENGTH 256
/* define the max lenght of match ethertype
 * max example: "ETHER_TYPE 65535"
 */
#define REDIS_CMD_ETYPE_MAX_LENGTH 20
/* define the max length of redis field/value command, ex,
 * DST_IPV6 2001:0000:130F:0000:0000:09C0:876A:130B/128
 */
#define REDIS_CMD_FIELD_VALUE_MAX_LENGTH 60


/* Configuration parameters. */
enum { MAX_METERS = 1 << 18 };  /* Maximum number of meters. */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */


/* Protects against changes to 'dp_netdevs'. */
struct ovs_mutex dp_sonic_mutex = OVS_MUTEX_INITIALIZER;

/* Interface to netdev-based datapath. */
struct dpif_sonic {
    struct dpif dpif;

    /* struct ovs_header. */
    int dp_ifindex;

    const char *name;

    //struct dp_netdev *dp;
    uint64_t last_port_seq;
};

struct dpif_sonic_flow_dump {
    struct dpif_flow_dump up;
    int status;
    struct ovs_mutex mutex;
};

struct dpif_sonic_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_sonic_flow_dump *dump;
    struct dpif_flow_stats stats;
    struct ofpbuf nl_flows;     /* Always used to store flows. */
    struct ofpbuf *nl_actions;  /* Used if kernel does not supply actions. */
    int netdev_dump_idx;        /* This thread current netdev dump index */
    bool netdev_done;           /* If we are finished dumping netdevs */
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
};

/* dpif_sonic_port_state stores key to getnext
 * use PORT_LOOP_GET_FIRST_IFINDEX_POSITION to get 1st data
 */
struct dpif_sonic_port_state {
    int ifindex_position;
};

/* open_dpif@netlink, create_dpif_netdev@netdev */
static int open_dpif(const char *name, struct dpif **dpifp);
static struct dpif_sonic *dpif_sonic_cast(const struct dpif *dpif);


static int dpif_sonic_init(void);
static int dpif_sonic_enumerate(struct sset *all_dps, const struct dpif_class *dpif_class OVS_UNUSED);
static const char *dpif_sonic_port_open_type(const struct dpif_class *class, const char *type);
static int dpif_sonic_open(const struct dpif_class *class OVS_UNUSED, const char *name, bool create, struct dpif **dpifp);
static void dpif_sonic_close(struct dpif *dpif_);
static int dpif_sonic_destroy(struct dpif *dpif);
static bool dpif_sonic_run(struct dpif *dpif_);
static void dpif_sonic_wait(struct dpif *dpif);
static int dpif_sonic_get_stats(const struct dpif *dpif_, struct dpif_dp_stats *stats);

static int dpif_sonic_port_add(struct dpif *dpif, struct netdev *netdev, odp_port_t *port_nop);
static int dpif_sonic_port_del(struct dpif *dpif, odp_port_t port_no);
static int dpif_sonic_port_set_config(struct dpif *dpif, odp_port_t port_no, const struct smap *cfg);

static int dpif_sonic_port_query_by_number(const struct dpif *dpif_, odp_port_t port_no, struct dpif_port *dpif_port);
static int dpif_sonic_port_query_by_name(const struct dpif *dpif_, const char *devname, struct dpif_port *dpif_port);

static uint32_t dpif_sonic_port_get_pid(const struct dpif *dpif_, odp_port_t port_no);
static int dpif_sonic_port_dump_start(const struct dpif *dpif_, void **statep);
static int dpif_sonic_port_dump_next(const struct dpif *dpif_, void *state_, struct dpif_port *dpif_port);
static int dpif_sonic_port_dump_done(const struct dpif *dpif_ OVS_UNUSED, void *state_);
static int dpif_sonic_port_poll(const struct dpif *dpif_, char **devnamep);
static void dpif_sonic_port_poll_wait(const struct dpif *dpif_);
static bool dpif_sonic_port_valid_flow_priority(struct dpif *dpif, odp_port_t port_no, int priority);
static int dpif_sonic_flow_flush(struct dpif *dpif);

static struct dpif_sonic_flow_dump *dpif_sonic_flow_dump_cast(struct dpif_flow_dump *dump);
static struct dpif_flow_dump *dpif_sonic_flow_dump_create(const struct dpif *dpif_, bool terse,
                             struct dpif_flow_dump_types *types OVS_UNUSED);
static int dpif_sonic_flow_dump_destroy(struct dpif_flow_dump *dump_);

static struct dpif_sonic_flow_dump_thread *dpif_sonic_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread);
static struct dpif_flow_dump_thread *dpif_sonic_flow_dump_thread_create(struct dpif_flow_dump *dump_);
static void dpif_sonic_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_);
static int dpif_sonic_flow_dump_next(struct dpif_flow_dump_thread *thread_, struct dpif_flow *flows, int max_flows);

static void dpif_sonic_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type OVS_UNUSED);
static int dpif_sonic_queue_to_priority(const struct dpif *dpif OVS_UNUSED, uint32_t queue_id, uint32_t *priority);

static void dpif_sonic_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb, void *aux);
static void dpif_sonic_register_upcall_cb(struct dpif *dpif, upcall_callback *cb, void *aux);
static void dpif_sonic_enable_upcall(struct dpif *dpif);
static void dpif_sonic_disable_upcall(struct dpif *dpif);

static char *dpif_sonic_get_datapath_version(void);
static void dpif_sonic_meter_get_features(const struct dpif * dpif OVS_UNUSED, struct ofputil_meter_features *features);
static int dpif_sonic_meter_set(struct dpif *dpif, ofproto_meter_id meter_id, struct ofputil_meter_config *config);
static int dpif_sonic_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands);
static int dpif_sonic_meter_del(struct dpif *dpif, ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands);

static bool odp_mask_attr_is_exact(const struct nlattr *ma);
static void ovs_key_attr_to_string(int attr, char *namebuf);
static void dpif_sonic_construct_ace_set(const struct nlattr *key, size_t key_len,
        const struct nlattr *mask, size_t mask_len, const struct nlattr *actions, size_t actions_len);
static void dpif_sonic_construct_ace_unset(const struct nlattr *key, size_t key_len);
static void dpif_sonic_print_flow(const struct nlattr *key, size_t key_len,
        const struct nlattr *mask, size_t mask_len, const struct nlattr *actions, size_t actions_len);
static void connectRedis(char *table_cmd_p, char *cmd_p, int type);


const struct dpif_class dpif_sonic_class = {
    "sonic",                    /* type */
    false,                       /* cleanup_required */
    false,                       /* synced_dp_layers */
    NULL,                       /* init in dpif_sonic_enumerate */
    dpif_sonic_enumerate,
    dpif_sonic_port_open_type,
    dpif_sonic_open,
    dpif_sonic_close,
    dpif_sonic_destroy,
    dpif_sonic_run,
    dpif_sonic_wait,
    dpif_sonic_get_stats,
    NULL,                      /* set_features */
    dpif_sonic_port_add,
    dpif_sonic_port_del,
    dpif_sonic_port_set_config,
    dpif_sonic_port_query_by_number,
    dpif_sonic_port_query_by_name,
    dpif_sonic_port_get_pid,
    dpif_sonic_port_dump_start,
    dpif_sonic_port_dump_next,
    dpif_sonic_port_dump_done,
    dpif_sonic_port_poll,
    dpif_sonic_port_poll_wait,
    dpif_sonic_port_valid_flow_priority,
    dpif_sonic_flow_flush,
    dpif_sonic_flow_dump_create,
    dpif_sonic_flow_dump_destroy,
    dpif_sonic_flow_dump_thread_create,
    dpif_sonic_flow_dump_thread_destroy,
    dpif_sonic_flow_dump_next,
    dpif_sonic_operate,
    NULL,                       /* offload_stats_get */
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */
    NULL,                       /* number_handlers_required */
    NULL,                       /* set_config */
    dpif_sonic_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_sonic_register_dp_purge_cb,
    dpif_sonic_register_upcall_cb,
    dpif_sonic_enable_upcall,
    dpif_sonic_disable_upcall,
    dpif_sonic_get_datapath_version,
    NULL,                       /* ct_dump_start */
    NULL,                       /* ct_dump_next */
    NULL,                       /* ct_dump_done */
    NULL,                       /* ct_flush */
    NULL,                       /* ct_set_maxconns */
    NULL,                       /* ct_get_maxconns */
    NULL,                       /* ct_get_nconns */
    NULL,                       /* ct_set_tcp_seq_chk */
    NULL,                       /* ct_get_tcp_seq_chk */
    NULL,                       /* ct_set_limits */
    NULL,                       /* ct_get_limits */
    NULL,                       /* ct_del_limits */
    NULL,                       /* ct_set_timeout_policy */
    NULL,                       /* ct_get_timeout_policy */
    NULL,                       /* ct_del_timeout_policy */
    NULL,                       /* ct_timeout_policy_dump_start */
    NULL,                       /* ct_timeout_policy_dump_next */
    NULL,                       /* ct_timeout_policy_dump_done */
    NULL,                       /* ct_get_timeout_policy_name */
    NULL,                       /* ct_get_features */
    NULL,                       /* ipf_set_enabled */
    NULL,                       /* ipf_set_min_frag */
    NULL,                       /* ipf_set_max_nfrags */
    NULL,                       /* ipf_get_status */
    NULL,                       /* ipf_dump_start */
    NULL,                       /* ipf_dump_next */
    NULL,                       /* ipf_dump_done */
    dpif_sonic_meter_get_features,
    dpif_sonic_meter_set,
    dpif_sonic_meter_get,
    dpif_sonic_meter_del,
    NULL,                       /* bond_add */
    NULL,                       /* bond_del */
    NULL,                       /* bond_stats_get */
    NULL,                       /* cache_get_supported_levels */
    NULL,                       /* cache_get_name */
    NULL,                       /* cache_get_size */
    NULL,                       /* cache_set_size */
};

/* Generic Netlink family numbers for OVS.
 *
 * Initialized by dpif_sonic_init().
static int ovs_datapath_family;
static int ovs_flow_family;
static int ovs_packet_family;
static int ovs_meter_family;
 */



/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
bool
dpif_is_sonic(const struct dpif *dpif)
{
    return dpif->dpif_class->open == dpif_sonic_open;
}


static int
open_dpif(const char *name, struct dpif **dpifp)
{
    struct dpif_sonic *dpif;

    dpif = xzalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, &dpif_sonic_class, name, 0, 0);
    dpif->dp_ifindex = 0;
    *dpifp = &dpif->dpif;
    return 0;
}

static struct dpif_sonic *
dpif_sonic_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_sonic_class);
    return CONTAINER_OF(dpif, struct dpif_sonic, dpif);
}

static int
dpif_sonic_init(void)
{
    static int error;

    netdev_sonic_port_init();
    return error;
}

/* Enumerates the names of all known created datapaths (of class
 * 'dpif_class'), if possible, into 'all_dps'.  The caller has already
 * initialized 'all_dps' and other dpif classes might already have added
 * names to it.
 *
 * This is used by the vswitch at startup, so that it can delete any
 * datapaths that are not configured.
 *
 * Some kinds of datapaths might not be practically enumerable, in which
 * case this function may be a null pointer. */
static int
dpif_sonic_enumerate(struct sset *all_dps,
                       const struct dpif_class *dpif_class OVS_UNUSED)
{
    int error = 0;

    error = dpif_sonic_init();

    if (error) {
        return error;
    }
    ovs_mutex_lock(&dp_sonic_mutex);
    sset_add(all_dps, "ovs-sonic");
    ovs_mutex_unlock(&dp_sonic_mutex);

    return 0;
}

static const char *
dpif_sonic_port_open_type(const struct dpif_class *class, const char *type)
{
    //return strcmp(type, "sonic") ? type : "sonic";
    return "sonic";
}

/* Attempts to open an existing dpif called 'name', if 'create' is false,
 * or to open an existing dpif or create a new one, if 'create' is true.
 *
 * 'dpif_class' is the class of dpif to open.
 *
 * If successful, stores a pointer to the new dpif in '*dpifp', which must
 * have class 'dpif_class'.  On failure there are no requirements on what
 * is stored in '*dpifp'. */
static int
dpif_sonic_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                  bool create, struct dpif **dpifp)
{
    int error = 0;

    error = dpif_sonic_init();

    if (error) {
        return error;
    }

    error = open_dpif(name, dpifp);
    return error;
}

/* Closes 'dpif' and frees associated memory. */
static void
dpif_sonic_close(struct dpif *dpif_)
{
    struct dpif_sonic *dpif = dpif_sonic_cast(dpif_);

    /* destroy all threads ???
     */

    free(dpif);
}

/* Attempts to destroy the dpif underlying 'dpif'.
 *
 * If successful, 'dpif' will not be used again except as an argument for
 * the 'close' member function. */
static int
dpif_sonic_destroy(struct dpif *dpif)
{
    /* do nothing, not allow to destroy DP ???
     */

    return 0;
}

/* Performs periodic work needed by 'dpif', if any is necessary.
 * Returns true if need to revalidate. */
static bool
dpif_sonic_run(struct dpif *dpif_)
{
    //struct dpif_sonic *dpif = dpif_sonic_cast(dpif_);
    /* check ports/flows ???
     */

    return false;
}

/* Arranges for poll_block() to wake up if the "run" member function needs
 * to be called for 'dpif'. */
static void
dpif_sonic_wait(struct dpif *dpif)
{

}

/* Retrieves statistics for 'dpif' into 'stats'. */
static int
dpif_sonic_get_stats(const struct dpif *dpif_, struct dpif_dp_stats *stats)
{
    //struct dpif_sonic *dpif = dpif_sonic_cast(dpif_);

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0; //initial

    /* get stats from sonic ???
     */
    return 0;
}


/* Adds 'netdev' as a new port in 'dpif'.  If '*port_no' is not
 * ODPP_NONE, attempts to use that as the port's port number.
 *
 * If port is successfully added, sets '*port_no' to the new port's
 * port number.  Returns EBUSY if caller attempted to choose a port
 * number, and it was in use. */
static int
dpif_sonic_port_add(struct dpif *dpif, struct netdev *netdev,
                     odp_port_t *port_no)
{
    return netdev_sonic_port_add(netdev_get_name(netdev), (int *)port_no);
}

/* Removes port numbered 'port_no' from 'dpif'. */
static int
dpif_sonic_port_del(struct dpif *dpif, odp_port_t port_no)
{
    return netdev_sonic_port_del(port_no);
}

/* Refreshes configuration of 'dpif's port. The implementation might
 * postpone applying the changes until run() is called. */
static int
dpif_sonic_port_set_config(struct dpif *dpif, odp_port_t port_no,
                            const struct smap *cfg)
{
    /* do nothing, not allow to set sonic port ???
     */

    return 0;
}

/* Queries 'dpif' for a port with the given 'port_no' or 'devname'.
 * If 'port' is not null, stores information about the port into
 * '*port' if successful.
 *
 * If the port doesn't exist, the provider must return ENODEV.  Other
 * error numbers means that something wrong happened and will be
 * treated differently by upper layers.
 *
 * If 'port' is not null, the caller takes ownership of data in
 * 'port' and must free it with dpif_port_destroy() when it is no
 * longer needed. */
static int
dpif_sonic_port_query_by_number(const struct dpif *dpif_, odp_port_t port_no,
                                  struct dpif_port *dpif_port)
{
    netdev_sonic_port_t data;

    memset(&data, 0, sizeof(data));

    if (0 == netdev_sonic_port_query_by_number(port_no, &data)) {
        dpif_port->name = xstrdup(data.name_ar);
        dpif_port->type = xstrdup("sonic");
        dpif_port->port_no = data.ifindex;
        return 0;
    }

    return ENODEV;
}

static int
dpif_sonic_port_query_by_name(const struct dpif *dpif_, const char *devname,
                              struct dpif_port *dpif_port)
{
    netdev_sonic_port_t data;

    memset(&data, 0, sizeof(data));

    if (0 == netdev_sonic_port_query_by_name(devname, &data))
    {
        dpif_port->name = xstrdup(data.name_ar);
        dpif_port->type = xstrdup("sonic");
        dpif_port->port_no = data.ifindex;
        return 0;
    }
    return ENODEV;
}

/* Returns the Netlink PID value to supply in OVS_ACTION_ATTR_USERSPACE
 * actions as the OVS_USERSPACE_ATTR_PID attribute's value, for use in
 * flows whose packets arrived on port 'port_no'.
 *
 * A 'port_no' of UINT32_MAX should be treated as a special case.  The
 * implementation should return a reserved PID, not allocated to any port,
 * that the client may use for special purposes.
 *
 * The return value only needs to be meaningful when DPIF_UC_ACTION has
 * been enabled in the 'dpif''s listen mask, and it is allowed to change
 * when DPIF_UC_ACTION is disabled and then re-enabled.
 *
 * A dpif provider that doesn't have meaningful Netlink PIDs can use NULL
 * for this function.  This is equivalent to always returning 0. */
static uint32_t
dpif_sonic_port_get_pid(const struct dpif *dpif_, odp_port_t port_no)
{

    return 0;
}

/* Attempts to begin dumping the ports in a dpif.  On success, returns 0
 * and initializes '*statep' with any data needed for iteration.  On
 * failure, returns a positive errno value. */
static int
dpif_sonic_port_dump_start(const struct dpif *dpif_, void **statep)
{
    //struct dpif_sonic *dpif = dpif_sonic_cast(dpif_);
    struct dpif_sonic_port_state *state;

    *statep = state = xmalloc(sizeof *state);
    state->ifindex_position = PORT_LOOP_GET_FIRST_IFINDEX_POSITION;
    return 0;
}

/* Attempts to retrieve another port from 'dpif' for 'state', which was
 * initialized by a successful call to the 'port_dump_start' function for
 * 'dpif'.  On success, stores a new dpif_port into 'port' and returns 0.
 * Returns EOF if the end of the port table has been reached, or a positive
 * errno value on error.  This function will not be called again once it
 * returns nonzero once for a given iteration (but the 'port_dump_done'
 * function will be called afterward).
 *
 * The dpif provider retains ownership of the data stored in 'port'.  It
 * must remain valid until at least the next call to 'port_dump_next' or
 * 'port_dump_done' for 'state'. */
static int
dpif_sonic_port_dump_next(const struct dpif *dpif_, void *state_,
                            struct dpif_port *dpif_port)
{
    //struct dpif_sonic *dpif = dpif_sonic_cast(dpif_);
    struct dpif_sonic_port_state *state = state_;
    netdev_sonic_port_t data;

    memset(&data, 0, sizeof(data));

    if (PORT_LOOP_GET_FIRST_IFINDEX_POSITION != state->ifindex_position) {
        strcpy(data.name_ar, dpif_port->name);
        data.ifindex = (dpif_port->port_no + 1);
    }

    if (0 == netdev_sonic_port_next(&data)) {
        dpif_port->name = xstrdup(data.name_ar);
        dpif_port->type = xstrdup("sonic");
        dpif_port->port_no = data.ifindex;
        state->ifindex_position = data.ifindex;
        return 0;
    }

    return EOF;  //end next ???
}

/* Releases resources from 'dpif' for 'state', which was initialized by a
 * successful call to the 'port_dump_start' function for 'dpif'.  */
static int
dpif_sonic_port_dump_done(const struct dpif *dpif_ OVS_UNUSED, void *state_)
{
    struct dpif_sonic_port_state *state = state_;

    free(state);
    /* free allocate by dpif_sonic_port_dump_start ???
    free(state);
     */
    return 0;
}

/* Polls for changes in the set of ports in 'dpif'.  If the set of ports in
 * 'dpif' has changed, then this function should do one of the
 * following:
 *
 * - Preferably: store the name of the device that was added to or deleted
 *   from 'dpif' in '*devnamep' and return 0.  The caller is responsible
 *   for freeing '*devnamep' (with free()) when it no longer needs it.
 *
 * - Alternatively: return ENOBUFS, without indicating the device that was
 *   added or deleted.
 *
 * Occasional 'false positives', in which the function returns 0 while
 * indicating a device that was not actually added or deleted or returns
 * ENOBUFS without any change, are acceptable.
 *
 * If the set of ports in 'dpif' has not changed, returns EAGAIN.  May also
 * return other positive errno values to indicate that something has gone
 * wrong. */
static int
dpif_sonic_port_poll(const struct dpif *dpif_, char **devnamep)
{

    /* monitor port change ???
     */
    return 0;
}

/* Arranges for the poll loop to wake up when 'port_poll' will return a
 * value other than EAGAIN. */
static void
dpif_sonic_port_poll_wait(const struct dpif *dpif_)
{

static bool dpif_sonic_port_valid_flow_priority(struct dpif *dpif,
                    odp_port_t port_no, int priority)
{
    return netdev_sonic_port_priority_valid((int) port_no, priority);
}

/* Deletes all flows from 'dpif' and clears all of its queues of received
 * packets. */
static int
dpif_sonic_flow_flush(struct dpif *dpif)
{

    return 0;
}


static struct dpif_sonic_flow_dump *
dpif_sonic_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_sonic_flow_dump, up);
}


/* Flow dumping interface.
 *
 * This is the back-end for the flow dumping interface described in
 * dpif.h.  Please read the comments there first, because this code
 * closely follows it.
 *
 * 'flow_dump_create' and 'flow_dump_thread_create' must always return an
 * initialized and usable data structure and defer error return until
 * flow_dump_destroy().  This hasn't been a problem for the dpifs that
 * exist so far.
 *
 * 'flow_dump_create' and 'flow_dump_thread_create' must initialize the
 * structures that they return with dpif_flow_dump_init() and
 * dpif_flow_dump_thread_init(), respectively.
 *
 * If 'terse' is true, then only UID and statistics will
 * be returned in the dump. Otherwise, all fields will be returned.
 *
 * If 'types' isn't null, dumps only the flows of the passed types. */
static struct dpif_flow_dump *
dpif_sonic_flow_dump_create(const struct dpif *dpif_, bool terse,
                             struct dpif_flow_dump_types *types OVS_UNUSED)
{
    struct dpif_sonic_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);

    dump->up.terse = terse;
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_sonic_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_sonic_flow_dump *dump = dpif_sonic_flow_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}


static struct dpif_sonic_flow_dump_thread *
dpif_sonic_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_sonic_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_sonic_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_sonic_flow_dump *dump = dpif_sonic_flow_dump_cast(dump_);
    struct dpif_sonic_flow_dump_thread *thread;


    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_sonic_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_sonic_flow_dump_thread *thread
        = dpif_sonic_flow_dump_thread_cast(thread_);

    free(thread);
}

static int
dpif_sonic_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                            struct dpif_flow *flows, int max_flows)
{
    struct dpif_sonic_flow_dump_thread *thread
        = dpif_sonic_flow_dump_thread_cast(thread_);
    struct dpif_sonic_flow_dump *dump = thread->dump;

    ovs_mutex_lock(&dump->mutex);

    ovs_mutex_unlock(&dump->mutex);
    return 0;
}

/* Executes each of the 'n_ops' operations in 'ops' on 'dpif', in the order
 * in which they are specified, placing each operation's results in the
 * "output" members documented in comments and the 'error' member of each
 * dpif_op. The offload_type argument tells the provider if 'ops' should
 * be submitted to to a netdev (only offload) or to the kernel datapath
 * (never offload) or to both (offload if possible; software fallback). */
static void
dpif_sonic_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type OVS_UNUSED)
{
    if (0 == n_ops) {
        return;
    }
    size_t i;

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;
        //struct dpif_flow_get *get;

        switch (op->type) {
            case DPIF_OP_FLOW_PUT: {
                VLOG_INFO("%s %d. DPIF_OP_FLOW_PUT", __FUNCTION__, __LINE__);
                put = &op->flow_put;
                dpif_sonic_construct_ace_set(put->key, put->key_len,
                        put->mask, put->mask_len, put->actions, put->actions_len);
                break;
            }

            case DPIF_OP_FLOW_DEL: {
                VLOG_INFO("%s %d. DPIF_OP_FLOW_DEL", __FUNCTION__, __LINE__);
                del = &op->flow_del;
                dpif_sonic_construct_ace_unset(del->key, del->key_len);
                break;
            }

            case DPIF_OP_FLOW_GET: {
                VLOG_INFO("%s %d. DPIF_OP_FLOW_GET", __FUNCTION__, __LINE__);
                //get = &op->flow_get;
                break;
            }
            case DPIF_OP_EXECUTE:
            default:
                VLOG_INFO("%s %d. not handle op->type:%d", __FUNCTION__, __LINE__, op->type);
        } /* switch (op->type) */
    }
}


/* Translates OpenFlow queue ID 'queue_id' (in host byte order) into a
 * priority value used for setting packet priority. */
static int
dpif_sonic_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{

    *priority = queue_id;
    return 0;
}


/* When 'dpif' is about to purge the datapath, the higher layer may want
 * to be notified so that it could try reacting accordingly (e.g. grabbing
 * all flow stats before they are gone).
 *
 * Registers an upcall callback function with 'dpif'.  This is only used
 * if 'dpif' needs to notify the purging of datapath.  'aux' is passed to
 * the callback on invocation. */
static void
dpif_sonic_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb,
                                 void *aux)
{

}

/* For datapaths that run in userspace (i.e. dpif-netdev), threads polling
 * for incoming packets can directly call upcall functions instead of
 * offloading packet processing to separate handler threads. Datapaths
 * that directly call upcall functions should use the functions below to
 * to register an upcall function and enable / disable upcalls.
 *
 * Registers an upcall callback function with 'dpif'. This is only used
 * if 'dpif' directly executes upcall functions. 'aux' is passed to the
 * callback on invocation. */
static void
dpif_sonic_register_upcall_cb(struct dpif *dpif, upcall_callback *cb,
                               void *aux)
{

}

/* Enables upcalls if 'dpif' directly executes upcall functions. */
static void
dpif_sonic_enable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{

}

/* Disables upcalls if 'dpif' directly executes upcall functions. */
static void
dpif_sonic_disable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{

}

/* Get datapath version. Caller is responsible for freeing the string
 * returned.  */
static char *
dpif_sonic_get_datapath_version(void)
{

    return xstrdup("<built-in>");
}


/* Queries 'dpif' for supported meter features.
 * NULL pointer means no meter features are supported. */
static void
dpif_sonic_meter_get_features(const struct dpif * dpif OVS_UNUSED,
                               struct ofputil_meter_features *features)
{

    features->max_meters = MAX_METERS;
    features->band_types = DP_SUPPORTED_METER_BAND_TYPES;
    features->capabilities = DP_SUPPORTED_METER_FLAGS_MASK;
    features->max_bands = MAX_BANDS;
    features->max_color = 0;
}

/* Adds or modifies the meter in 'dpif' with the given 'meter_id'
 * and the configuration in 'config'.
 *
 * The meter id specified through 'config->meter_id' is ignored. */
static int
dpif_sonic_meter_set(struct dpif *dpif, ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config)
{

    return 0;
}

/* Queries 'dpif' for meter stats with the given 'meter_id'.  Stores
 * maximum of 'n_bands' meter statistics, returning the number of band
 * stats returned in 'stats->n_bands' if successful. */
static int
dpif_sonic_meter_get(const struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{

    return 0;
}

/* Removes meter 'meter_id' from 'dpif'. Stores meter and band statistics
 * (for maximum of 'n_bands', returning the number of band stats returned
 * in 'stats->n_bands' if successful.  'stats' may be passed in as NULL if
 * no stats are needed, in which case 'n_bands' must be passed in as
 * zero. */
static int
dpif_sonic_meter_del(struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{

    return 0;
}

// same as odp_mask_attr_is_exact
static bool
odp_mask_attr_is_exact(const struct nlattr *ma)
{
    int /*enum ovs_key_attr*/ attr = nl_attr_type(ma);
    const void *mask = nl_attr_get(ma);
    size_t size = nl_attr_get_size(ma);
    int constant = -1;
    uint8_t u8 = constant;

    switch (attr) {
        case OVS_KEY_ATTR_UNSPEC:
        case OVS_KEY_ATTR_ENCAP:
        case __OVS_KEY_ATTR_MAX:
        default:
            return false;

        case OVS_KEY_ATTR_PRIORITY:
        case OVS_KEY_ATTR_IN_PORT:
        case OVS_KEY_ATTR_ETHERNET:
        case OVS_KEY_ATTR_VLAN:
        case OVS_KEY_ATTR_ETHERTYPE:
        case OVS_KEY_ATTR_IPV4:
        case OVS_KEY_ATTR_TCP:
        case OVS_KEY_ATTR_UDP:
        case OVS_KEY_ATTR_ICMP:
        case OVS_KEY_ATTR_ICMPV6:
        case OVS_KEY_ATTR_ND:
        case OVS_KEY_ATTR_ND_EXTENSIONS:
        case OVS_KEY_ATTR_SKB_MARK:
        case OVS_KEY_ATTR_TUNNEL:
        case OVS_KEY_ATTR_SCTP:
        case OVS_KEY_ATTR_DP_HASH:
        case OVS_KEY_ATTR_RECIRC_ID:
        case OVS_KEY_ATTR_MPLS:
        case OVS_KEY_ATTR_CT_STATE:
        case OVS_KEY_ATTR_CT_ZONE:
        case OVS_KEY_ATTR_CT_MARK:
        case OVS_KEY_ATTR_CT_LABELS:
        case OVS_KEY_ATTR_PACKET_TYPE:
        case OVS_KEY_ATTR_NSH: {
            const uint8_t *p = mask;
            size_t i;

            for (i = 0; i < size; i++) {
                if (p[i] != u8) {
                    return false;
                }
            }
            return true;
        }
    }
    return false;
}

//ovs_key_attr_to_string same as odp-util.c
static void
ovs_key_attr_to_string(int attr, char *namebuf)
{
    switch (attr) {
        case OVS_KEY_ATTR_UNSPEC:
            strcpy(namebuf, "unspec");
            break;
        case OVS_KEY_ATTR_ENCAP:
            strcpy(namebuf, "encap");
            break;
        case OVS_KEY_ATTR_PRIORITY:
            strcpy(namebuf, "skb_priority");
            break;
        case OVS_KEY_ATTR_SKB_MARK:
            strcpy(namebuf, "skb_mark");
            break;
        case OVS_KEY_ATTR_CT_STATE:
            strcpy(namebuf, "ct_state");
            break;
        case OVS_KEY_ATTR_CT_ZONE:
            strcpy(namebuf, "ct_zone");
            break;
        case OVS_KEY_ATTR_CT_MARK:
            strcpy(namebuf, "ct_mark");
            break;
        case OVS_KEY_ATTR_CT_LABELS:
            strcpy(namebuf, "ct_label");
            break;
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
            strcpy(namebuf, "ct_tuple4");
            break;
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
            strcpy(namebuf, "ct_tuple6");
            break;
        case OVS_KEY_ATTR_TUNNEL:
            strcpy(namebuf, "tunnel");
            break;
        case OVS_KEY_ATTR_IN_PORT:
            strcpy(namebuf, "in_port");
            break;
        case OVS_KEY_ATTR_ETHERNET:
            strcpy(namebuf, "eth");
            break;
        case OVS_KEY_ATTR_VLAN:
            strcpy(namebuf, "vlan");
            break;
        case OVS_KEY_ATTR_ETHERTYPE:
            strcpy(namebuf, "eth_type");
            break;
        case OVS_KEY_ATTR_IPV4:
            strcpy(namebuf, "ipv4");
            break;
        case OVS_KEY_ATTR_IPV6:
            strcpy(namebuf, "ipv6");
            break;
        case OVS_KEY_ATTR_TCP:
            strcpy(namebuf, "tcp");
            break;
        case OVS_KEY_ATTR_TCP_FLAGS:
            strcpy(namebuf, "tcp_flags");
            break;
        case OVS_KEY_ATTR_UDP:
            strcpy(namebuf, "udp");
            break;
        case OVS_KEY_ATTR_SCTP:
            strcpy(namebuf, "sctp");
            break;
        case OVS_KEY_ATTR_ICMP:
            strcpy(namebuf, "icmp");
            break;
        case OVS_KEY_ATTR_ICMPV6:
            strcpy(namebuf, "icmpv6");
            break;
        case OVS_KEY_ATTR_ARP:
            strcpy(namebuf, "arp");
            break;
        case OVS_KEY_ATTR_ND:
            strcpy(namebuf, "nd");
            break;
        case OVS_KEY_ATTR_ND_EXTENSIONS:
            strcpy(namebuf, "nd_ext");
            break;
        case OVS_KEY_ATTR_MPLS:
            strcpy(namebuf, "mpls");
            break;
        case OVS_KEY_ATTR_DP_HASH:
            strcpy(namebuf, "dp_hash");
            break;
        case OVS_KEY_ATTR_RECIRC_ID:
            strcpy(namebuf, "recirc_id");
            break;
        case OVS_KEY_ATTR_PACKET_TYPE:
            strcpy(namebuf, "packet_type");
            break;
        case OVS_KEY_ATTR_NSH:
            strcpy(namebuf, "nsh");
            break;

        default:
            sprintf(namebuf, "key%u", (unsigned int) attr);
            break;
    }
}

static int
odp_action_len(uint16_t type)
{
    if (type > OVS_ACTION_ATTR_MAX) {
        return -1;
    }

    switch (type) {
        case OVS_ACTION_ATTR_OUTPUT: return sizeof(uint32_t);
        case OVS_ACTION_ATTR_LB_OUTPUT: return sizeof(uint32_t);
        case OVS_ACTION_ATTR_TRUNC: return sizeof(struct ovs_action_trunc);
        case OVS_ACTION_ATTR_TUNNEL_PUSH: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_TUNNEL_POP: return sizeof(uint32_t);
        case OVS_ACTION_ATTR_METER: return sizeof(uint32_t);
        case OVS_ACTION_ATTR_USERSPACE: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_PUSH_VLAN: return sizeof(struct ovs_action_push_vlan);
        case OVS_ACTION_ATTR_POP_VLAN: return 0;
        case OVS_ACTION_ATTR_PUSH_MPLS: return sizeof(struct ovs_action_push_mpls);
        case OVS_ACTION_ATTR_POP_MPLS: return sizeof(ovs_be16);
        case OVS_ACTION_ATTR_RECIRC: return sizeof(uint32_t);
        case OVS_ACTION_ATTR_HASH: return sizeof(struct ovs_action_hash);
        case OVS_ACTION_ATTR_SET: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_SET_MASKED: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_SAMPLE: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_CT: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_CT_CLEAR: return 0;
        case OVS_ACTION_ATTR_PUSH_ETH: return sizeof(struct ovs_action_push_eth);
        case OVS_ACTION_ATTR_POP_ETH: return 0;
        case OVS_ACTION_ATTR_CLONE: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_PUSH_NSH: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_POP_NSH: return 0;
        case OVS_ACTION_ATTR_CHECK_PKT_LEN: return ATTR_LEN_VARIABLE;
        case OVS_ACTION_ATTR_ADD_MPLS: return sizeof(struct ovs_action_add_mpls);
        case OVS_ACTION_ATTR_DROP: return sizeof(uint32_t);

        case OVS_ACTION_ATTR_UNSPEC:
        case __OVS_ACTION_ATTR_MAX:
            return ATTR_LEN_INVALID;
    }

    return ATTR_LEN_INVALID;
}

/* get prefix of ip address
 * ipaddr_p (input)
 * prefix_p (output)
 * return true if success
 */
static bool dpif_sonic_get_v4prefix(char *ipaddr_p, int *prefix_p)
{
    int n = 0;
    int i = 0;

    /* inet_pton() returns 1 on success (network address was successfully converted).
     */
    if (!inet_pton(AF_INET, ipaddr_p, &n)) {
        return false;
    }

    while (n > 0) {
        n = n >> 1;
        i++;
    }
    return true;
}

static void dpif_sonic_get_v6prefix(const struct in6_addr *ipaddr_p, int *prefix_p)
{
    int i = 0;
    int bits = 0;

    for (i = 0; i < 16; i++) {
        switch (ipaddr_p->s6_addr[i]) {
            case 0xFF:
                bits += 8;
                break;
            case 0xFE:
                bits += 7;
                break;
            case 0xFC:
                bits += 6;
                break;
            case 0xF8:
                bits += 5;
                break;
            case 0xF0:
                bits += 4;
                break;
            case 0xE0:
                bits += 3;
                break;
            case 0xC0:
                bits += 2;
                break;
            case 0x80:
                bits += 1;
                break;
            default:
                break;
        }
    }
    *prefix_p = bits;
}

/* construct ACL table name
 * name_p (output): ACL table name ["ACL_TABLE|ACL_ETH0", "ACL_TABLE|ACL_ETH0v6"]
 * port_p (input): port name
 * table_type (input): ACL table type [NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3/NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3V6]
 */
static void dpif_sonic_construct_acl_table_name(char *name_p, char * port_p, int table_type)
{
    if (NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3 == table_type) {
        sprintf(name_p, "ACL_TABLE|%s", port_p);
    } else {
        sprintf(name_p, "ACL_TABLE|%sv6", port_p);
    }
}

/* construct ACE name
 * name_p (output): ACL table name
 *     ["ACL_RULE|ACL_ETH<port>|<priority>", "ACL_RULE|ACL_ETH<port>v6|<priority>"]
 * port_p (input): port name
 * prority (input): ACE prority
 * table_type (input): ACL table type [NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3/NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3V6]
 */
static void dpif_sonic_construct_ace_name(char *name_p, char * port_p, int prority, int table_type)
{
    if (NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3 == table_type) {
        sprintf(name_p, "ACL_RULE|%s|%d", port_p, prority);
    } else {
        sprintf(name_p, "ACL_RULE|%sv6|%d", port_p, prority);
    }
}

static void dpif_sonic_construct_ace_set(const struct nlattr *key, size_t key_len,
        const struct nlattr *mask, size_t mask_len, const struct nlattr *actions, size_t actions_len)
{
    /* initial ifindex to -1 (because real sonic port start from 0)
     */
    char cmd_ar[REDIS_CMD_MAX_LENGTH] = {0};
    char etype_cmd_ar[REDIS_CMD_ETYPE_MAX_LENGTH] = {0};
    int ifindex = INVALID_IFINDEX;
    int priority = 0;
    int table_type = NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3;

    if (0 == actions_len) {
        return;
    }

    if (0 != key_len) {
        const struct nlattr *a;
        unsigned int left;
        NL_ATTR_FOR_EACH (a, left, key, key_len) {
            int /*enum ovs_key_attr*/ attr_type = nl_attr_type(a);
            //ma is used to get mask value
            const struct nlattr *ma = (mask && mask_len
                           ? nl_attr_find__(mask, mask_len, attr_type) : NULL);

            if (mask && mask_len) {
                ma = nl_attr_find__(mask, mask_len, nl_attr_type(a));
            }

            switch (attr_type) {
                case OVS_KEY_ATTR_PRIORITY: {
                    priority = nl_attr_get_be32(a);
                    VLOG_INFO("%s %d. priority:%u.", __FUNCTION__, __LINE__, priority);
                    break;
                }

                case OVS_KEY_ATTR_IN_PORT: {
                    bool is_exact = ma ? odp_mask_attr_is_exact(ma) : true;
                    int attr_mask = 0;

                    if (!is_exact) {
                        attr_mask = nl_attr_get_be32(ma);
                    }

                    if (0 != attr_mask) {
                        ifindex = nl_attr_get_be32(a); //if mask ???
                        VLOG_INFO("%s %d. inport:%u.", __FUNCTION__, __LINE__, nl_attr_get_be32(a));
                        VLOG_INFO("%s %d. mask:%x.", __FUNCTION__, __LINE__, nl_attr_get_be32(ma));
                    }
                    break;
                }

                case OVS_KEY_ATTR_ETHERNET: {
                    const struct ovs_key_ethernet *attrmask = ma ? nl_attr_get(ma) : NULL;
                    const struct ovs_key_ethernet *attrkey = nl_attr_get(a);
                    const struct eth_addr src_key = attrkey->eth_src;
                    const struct eth_addr dst_key = attrkey->eth_dst;
                    const struct eth_addr *src_mask = MASK(attrmask, eth_src);
                    const struct eth_addr *dst_mask = MASK(attrmask, eth_dst);

                    if (src_mask && !eth_addr_is_zero(*src_mask)) {
                        VLOG_WARN("NOT handle SA:"ETH_ADDR_FMT".", ETH_ADDR_ARGS(src_key));
                        VLOG_INFO("%s %d. SA:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(src_key));
                        VLOG_INFO("%s %d. SA mask:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(*src_mask));
                    }

                    if (dst_mask && !eth_addr_is_zero(*dst_mask)) {
                        VLOG_WARN("NOT handle DA:"ETH_ADDR_FMT".", ETH_ADDR_ARGS(dst_key));
                        VLOG_INFO("%s %d. DA:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(dst_key));
                        VLOG_INFO("%s %d. DA mask:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(*dst_mask));
                    }
                    break;
                }

                case OVS_KEY_ATTR_VLAN: {
                    ovs_be16 tci = nl_attr_get_be16(a);
                    ovs_be16 tci_mask = (ma ? nl_attr_get_be16(ma) : OVS_BE16_MAX);

                    if (0 != vlan_tci_to_vid(tci_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};
                        ovs_be16 field_mask = vlan_tci_to_vid(tci_mask);

                        /* not allow mask by SONiC => set asci failed */
                        sprintf(filed_value_ar, " VLAN_ID %u", vlan_tci_to_vid(tci));
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. vid:%u.", __FUNCTION__, __LINE__, vlan_tci_to_vid(tci));
                        VLOG_INFO("%s %d. mask:%x.", __FUNCTION__, __LINE__, field_mask);
                    }
                    if (0 != vlan_tci_to_pcp(tci_mask)) {
                        /* SONiC: vlan pri is not supported on this ACL table*/
                        VLOG_WARN("NOT handle vlan pcp:%u.", vlan_tci_to_pcp(tci));
                        VLOG_INFO("%s %d. vlan pcp:%u.", __FUNCTION__, __LINE__, vlan_tci_to_pcp(tci));
                    }
                    break;
                }

                case OVS_KEY_ATTR_ETHERTYPE: {
                    ovs_be16 etype_mask = (ma ? nl_attr_get_be16(ma) : OVS_BE16_MAX);
                    ovs_be16 etype_key = ntohs(nl_attr_get_be16(a));
                    VLOG_INFO("%s %d. etype:%u/0x%x.", __FUNCTION__, __LINE__, etype_key, etype_mask);
                    /* when match VLAN, ethertype is 0x8100, upper layer ignores this.
                     * when match IPv4, ethertype is 0x800, upper layer ignores this.
                     * when match IPv6, ethertype is 0x86dd, upper layer ignores this.
                     */
                    if ((0 != etype_mask) && (0 != etype_key)) {
                        /* not allow mask by openflow standard */
                        sprintf(etype_cmd_ar, " ETHER_TYPE %u", etype_key);
                        VLOG_INFO("%s %d. etype:%u.", __FUNCTION__, __LINE__, etype_key);
                    }
                    break;
                }

                case OVS_KEY_ATTR_IPV4: {
                    const struct ovs_key_ipv4 *attrkey = nl_attr_get(a);
                    const struct ovs_key_ipv4 *attrmask = ma ? nl_attr_get(ma) : NULL;
                    ovs_be32 src_key = attrkey->ipv4_src;
                    ovs_be32 dst_key = attrkey->ipv4_dst;
                    uint8_t proto = attrkey->ipv4_proto;
                    uint8_t tos = attrkey->ipv4_tos;
                    uint8_t ttl = attrkey->ipv4_ttl;
                    uint8_t frag = attrkey->ipv4_frag;
                    const ovs_be32 *src_mask = MASK(attrmask, ipv4_src);
                    const ovs_be32 *dst_mask = MASK(attrmask, ipv4_dst);
                    const uint8_t *proto_mask = MASK(attrmask, ipv4_proto);
                    const uint8_t *tos_mask = MASK(attrmask, ipv4_tos);
                    const uint8_t *ttl_mask = MASK(attrmask, ipv4_ttl);
                    const uint8_t *frag_mask = MASK(attrmask, ipv4_frag);

                    if (src_mask && (0 != *src_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};
                        //ovs_be32 field_mask = IP_ARGS(*src_mask);

                        if (OVS_BE32_MAX == *src_mask) {
                            sprintf(filed_value_ar, " SRC_IP "IP_FMT"", IP_ARGS(src_key));
                        } else {
                            if (!ip_is_cidr(*src_mask)) {
                                VLOG_WARN("Invalid CIDR of SIP:"IP_FMT".", IP_ARGS(*src_mask));
                                continue;
                            }
                            int prefix = ip_count_cidr_bits(*src_mask);
                            sprintf(filed_value_ar, " SRC_IP "IP_FMT"/%u", IP_ARGS(src_key), prefix);
                        }
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. SIP:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(src_key));
                        VLOG_INFO("%s %d. SIP mask:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(*src_mask));
                    }
                    if (dst_mask && (0 != *dst_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};
                        //ovs_be32 field_mask = IP_ARGS(*dst_mask);

                        if (OVS_BE32_MAX == *dst_mask) {
                            sprintf(filed_value_ar, " DST_IP "IP_FMT"", IP_ARGS(dst_key));
                        } else {
                            if (!ip_is_cidr(*dst_mask)) {
                                VLOG_WARN("Invalid CIDR of DIP:"IP_FMT".", IP_ARGS(*dst_mask));
                                continue;
                            }
                            int prefix = ip_count_cidr_bits(*dst_mask);
                            sprintf(filed_value_ar, " DST_IP "IP_FMT"/%u", IP_ARGS(dst_key), prefix);
                        }
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. DIP:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(dst_key));
                        VLOG_INFO("%s %d. DIP mask:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(*dst_mask));
                    }
                    if (proto_mask && (0 != *proto_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};

                        /* not allow mask by openflow standard */
                        sprintf(filed_value_ar, " IP_PROTOCOL %d", proto);
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. IP protocol:%d.", __FUNCTION__, __LINE__, proto);
                    }
                    if (tos_mask && (0 != *tos_mask)) {
                        /* not allow mask by openflow standard */
                        VLOG_WARN("NOT handle IP tos:%d.", tos);
                        VLOG_INFO("%s %d. IP tos:%d.", __FUNCTION__, __LINE__, tos);
                    }
                    if (ttl_mask && (0 != *ttl_mask)) {
                        /* not allow mask by openflow standard */
                        VLOG_WARN("NOT handle IP ttl:%d.", ttl);
                        VLOG_INFO("%s %d. IP TTL:%d.", __FUNCTION__, __LINE__, ttl);
                    }
                    if (frag_mask && (0 != *frag_mask)) {
                        /* not allow mask by openflow standard */
                        VLOG_WARN("NOT handle IP frag:%d.", frag);
                        VLOG_INFO("%s %d. IP frag:%d.", __FUNCTION__, __LINE__, frag);
                    }
                    break;
                }

                case OVS_KEY_ATTR_TCP:
                case OVS_KEY_ATTR_UDP:
                case OVS_KEY_ATTR_SCTP: {
                    const struct ovs_key_tcp *attrkey = nl_attr_get(a);
                    const struct ovs_key_tcp *attrmask = ma ? nl_attr_get(ma) : NULL;
                    ovs_be16 src_key = attrkey->tcp_src;
                    ovs_be16 dst_key = attrkey->tcp_dst;
                    const ovs_be16 *src_mask = MASK(attrmask, tcp_src);
                    const ovs_be16 *dst_mask = MASK(attrmask, tcp_dst);

                    if (src_mask && (0 != *src_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};

                        /* not allow mask by openflow standard */
                        sprintf(filed_value_ar, " L4_SRC_PORT %d", ntohs(src_key));
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. L4 src:%d.", __FUNCTION__, __LINE__, ntohs(src_key));
                    }
                    if (dst_mask && (0 != *dst_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};

                        /* not allow mask by openflow standard */
                        sprintf(filed_value_ar, " L4_DST_PORT %d", ntohs(dst_key));
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. L4 dst:%d.", __FUNCTION__, __LINE__, ntohs(dst_key));
                    }
                    break;
                }

                case OVS_KEY_ATTR_TCP_FLAGS: {
                    if (ma && (0 != nl_attr_get_be16(ma))) {
                        /* not allow mask by openflow standard */
                        VLOG_WARN("NOT handle TCP flags:%u.", ntohs(nl_attr_get_be16(a)));
                        VLOG_INFO("%s %d. TCP flags:%u.", __FUNCTION__, __LINE__, ntohs(nl_attr_get_be16(a)));
                    }
                    break;
                }

                case OVS_KEY_ATTR_ICMP: {
                    const struct ovs_key_icmp *attrkey = nl_attr_get(a);
                    const struct ovs_key_icmp *attrmask = ma ? nl_attr_get(ma) : NULL;
                    uint8_t type_key = attrkey->icmp_type;
                    uint8_t code_key = attrkey->icmp_code;
                    const uint8_t *type_mask = MASK(attrmask, icmp_type);
                    const uint8_t *code_mask = MASK(attrmask, icmp_code);

                    if (type_mask && (0 != *type_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};

                        /* not allow mask by openflow standard */
                        sprintf(filed_value_ar, " ICMP_TYPE %d", type_key);
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. ICMP type:%d.", __FUNCTION__, __LINE__, type_key);
                    }
                    if (code_mask && (0 != *code_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};

                        /* not allow mask by openflow standard */
                        sprintf(filed_value_ar, " ICMP_CODE %d", code_key);
                        strcat(cmd_ar, filed_value_ar);
                        VLOG_INFO("%s %d. ICMP code:%d.", __FUNCTION__, __LINE__, code_key);
                    }
                    break;
                }

                case OVS_KEY_ATTR_IPV6: {
                    const struct ovs_key_ipv6 *attrkey = nl_attr_get(a);
                    const struct ovs_key_ipv6 *attrmask = ma ? nl_attr_get(ma) : NULL;
                    const struct in6_addr *src_key = &attrkey->ipv6_src;
                    const struct in6_addr *dst_key = &attrkey->ipv6_dst;
                    const struct in6_addr *src_mask = MASK(attrmask, ipv6_src);
                    const struct in6_addr *dst_mask = MASK(attrmask, ipv6_dst);

                    if (src_mask && !ipv6_mask_is_any(src_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};
                        char v6_buf_ar[INET6_ADDRSTRLEN] = {0};
                        inet_ntop(AF_INET6, src_key, v6_buf_ar, sizeof v6_buf_ar);

                        if (ipv6_mask_is_exact(src_mask)) {
                            sprintf(filed_value_ar, " SRC_IPV6 %s", v6_buf_ar);
                        } else {
                            if (!ipv6_is_cidr(src_mask)) {
                                inet_ntop(AF_INET6, src_mask, v6_buf_ar, sizeof v6_buf_ar);
                                VLOG_WARN("Invalid CIDR of SIPv6:%s.", v6_buf_ar);
                                continue;
                            }
                            int prefix = ipv6_count_cidr_bits(src_mask);
                            sprintf(filed_value_ar, " SRC_IPV6 %s/%u", v6_buf_ar, prefix);
                        }
                        strcat(cmd_ar, filed_value_ar);
                        table_type = NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3V6;
                        VLOG_INFO("%s %d. SIPv6:%s.", __FUNCTION__, __LINE__, v6_buf_ar);
                        inet_ntop(AF_INET6, src_mask, v6_buf_ar, sizeof v6_buf_ar);
                        VLOG_INFO("%s %d. SIPv6 mask:%s.", __FUNCTION__, __LINE__, v6_buf_ar);
                    }
                    if (dst_mask && !ipv6_mask_is_any(dst_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};
                        char v6_buf_ar[INET6_ADDRSTRLEN] = {0};
                        inet_ntop(AF_INET6, dst_key, v6_buf_ar, sizeof v6_buf_ar);

                        if (ipv6_mask_is_exact(dst_mask)) {
                            sprintf(filed_value_ar, " DST_IPV6 %s", v6_buf_ar);
                        } else {
                            if (!ipv6_is_cidr(dst_mask)) {
                                inet_ntop(AF_INET6, dst_mask, v6_buf_ar, sizeof v6_buf_ar);
                                VLOG_WARN("Invalid CIDR of DIPv6:%s.", v6_buf_ar);
                                continue;
                            }
                            int prefix = ipv6_count_cidr_bits(dst_mask);
                            sprintf(filed_value_ar, " DST_IPV6 %s/%u", v6_buf_ar, prefix);
                        }
                        strcat(cmd_ar, filed_value_ar);
                        table_type = NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3V6;
                        VLOG_INFO("%s %d. DIPv6:%s.", __FUNCTION__, __LINE__, v6_buf_ar);
                        inet_ntop(AF_INET6, dst_mask, v6_buf_ar, sizeof v6_buf_ar);
                        VLOG_INFO("%s %d. DIPv6 mask:%s.", __FUNCTION__, __LINE__, v6_buf_ar);
                    }
                    break;
                }

                case OVS_KEY_ATTR_ICMPV6: {
                    const struct ovs_key_icmpv6 *attrkey = nl_attr_get(a);
                    const struct ovs_key_icmpv6 *attrmask = ma ? nl_attr_get(ma) : NULL;
                    uint8_t type_key = attrkey->icmpv6_type;
                    uint8_t code_key = attrkey->icmpv6_code;
                    const uint8_t *type_mask = MASK(attrmask, icmpv6_type);
                    const uint8_t *code_mask = MASK(attrmask, icmpv6_code);

                    if (type_mask && (0 != *type_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};

                        /* not allow mask by openflow standard */
                        sprintf(filed_value_ar, " ICMPV6_TYPE %d", type_key);
                        strcat(cmd_ar, filed_value_ar);
                        table_type = NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3V6;
                        VLOG_INFO("%s %d. ICMPv6 type:%d.", __FUNCTION__, __LINE__, type_key);
                    }
                    if (code_mask && (0 != *code_mask)) {
                        char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};

                        /* not allow mask by openflow standard */
                        sprintf(filed_value_ar, " ICMPV6_CODE %d", code_key);
                        strcat(cmd_ar, filed_value_ar);
                        table_type = NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3V6;
                        VLOG_INFO("%s %d. ICMPv6 code:%d.", __FUNCTION__, __LINE__, code_key);
                    }
                    break;
                }

                default: {
                    char namebuf[OVS_KEY_ATTR_STR_SIZE] = {0};
                    ovs_key_attr_to_string(attr_type, namebuf);
                }
            }
        }
    }

    /* set type before action */
    if (NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3 == table_type) {
        if (0 != strlen(etype_cmd_ar)) {
            strcat(cmd_ar, etype_cmd_ar);
        }
        strcat(cmd_ar, " IP_TYPE IPV4ANY");
    } else {
        /* SONiC limitation: cannot set ethertype for IPv6
         */
        strcat(cmd_ar, " IP_TYPE IPV6ANY");
    }

    if (0 != actions_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
            int type = nl_attr_type(a);
            int expected_len = odp_action_len(nl_attr_type(a));

            if ((expected_len != ATTR_LEN_VARIABLE) && (nl_attr_get_size(a) != expected_len)) {
                VLOG_ERR("%s %d. bad length:expect %ld for:%d", __FUNCTION__, __LINE__, nl_attr_get_size(a), expected_len);
                return;
            }

            switch (type) {
                case OVS_ACTION_ATTR_OUTPUT: {
                    char filed_value_ar[REDIS_CMD_FIELD_VALUE_MAX_LENGTH] = {0};
                    char name_ar[NETDEV_SONIC_PORT_MAX_NAME_LEN] = {0};
                    int port_no = nl_attr_get_u32(a);

                    if (0xfffa == port_no) {  /* OFPP_NORMAL */
                        strcat(cmd_ar, " PACKET_ACTION FORWARD");
                    } else {
                        if (netdev_sonic_port_name_by_number(port_no, name_ar)) {
                            netdev_sonic_port_name_by_number(port_no, name_ar);
                            sprintf(filed_value_ar, " REDIRECT_ACTION %s", name_ar);
                            strcat(cmd_ar, filed_value_ar);
                        }
                    }

                    VLOG_INFO("%s %d. OVS_ACTION_ATTR_OUTPUT %u.", __FUNCTION__, __LINE__, nl_attr_get_u32(a));
                    break;
                }
                case OVS_ACTION_ATTR_DROP: {
                    strcat(cmd_ar, " PACKET_ACTION DROP");
                    VLOG_INFO("%s %d. OVS_ACTION_ATTR_DROP", __FUNCTION__, __LINE__);
                    break;
                }

                default:
                    strcat(cmd_ar, " PACKET_ACTION FORWARD");
                    VLOG_INFO("%s %d. not handle %d.", __FUNCTION__, __LINE__, type);
                    break;
            }
        }
    }
    /* hset ACL_RULE|ACL_ETH999|65535 PRIORITY 65535
        VLAN_ID 4094 SRC_IP 192.168.111.100/32 DST_IP 192.168.111.101/32
        IP_PROTOCOL 255 L4_SRC_PORT 65535 L4_DST_PORT 65533
        IP_TYPE IPV4ANY ICMP_CODE 255 ICMP_TYPE 233 ETHER_TYPE 0x8892
        REDIRECT_ACTION Ethernet999
     */

    if (INVALID_IFINDEX == ifindex) {
        VLOG_ERR("NOT handle the flow. Must specified in_port of flow.");
        return;
    } else {
        char redis_cmd_ar[REDIS_CMD_MAX_LENGTH] = {0};
        char ace_name_ar[REDIS_CMD_ACL_TABLE_NAME_LEN] = {0};
        char port_ar[REDIS_CMD_MAX_LENGTH] = {0};

        if (!netdev_sonic_port_name_by_number(ifindex, port_ar)) {
            VLOG_WARN("NOT handle the flow. Invalid in_port %d of flow.", ifindex);
            return;
        }

        dpif_sonic_construct_ace_name(ace_name_ar, port_ar, priority, table_type);
        sprintf(redis_cmd_ar, "HSET %s PRIORITY %d%s", ace_name_ar, priority, cmd_ar);
        VLOG_INFO("%s %d. %s.", __FUNCTION__, __LINE__, redis_cmd_ar);

        if (netdev_sonic_port_acl_set(ifindex, priority, table_type, true)) {
            char table_cmd_ar[REDIS_CMD_MAX_LENGTH] = {0};
            char table_ar[REDIS_CMD_MAX_LENGTH] = {0};
            dpif_sonic_construct_acl_table_name(table_ar, port_ar, table_type);

            sprintf(table_cmd_ar, "HSET %s policy_desc %s_in ports@ %s stage ingress type %s",
                    table_ar, port_ar, port_ar,
                    ((NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3 == table_type) ? "L3" : "L3V6"));
            VLOG_INFO("%s %d. %s.", __FUNCTION__, __LINE__, table_cmd_ar);
            connectRedis(table_cmd_ar, redis_cmd_ar, REDIS_CMD_TYPE_ADD);
        } else {
            connectRedis(NULL, redis_cmd_ar, REDIS_CMD_TYPE_ADD);
        }

        /* update store after REDIS
         */
        netdev_sonic_port_priority_set(ifindex, priority, table_type, true);
    }
}

static void dpif_sonic_construct_ace_unset(const struct nlattr *key, size_t key_len)
{
    /* initial ifindex to -1 (because real sonic port start from 0)
     */
    int ifindex = INVALID_IFINDEX;
    int priority = 0;
    int table_type = NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3;

    if (0 == key_len) {
        return;
    }

    if (0 != key_len) {
        const struct nlattr *a;
        unsigned int left;
        NL_ATTR_FOR_EACH (a, left, key, key_len) {
            int /*enum ovs_key_attr*/ attr_type = nl_attr_type(a);

            switch (attr_type) {
                case OVS_KEY_ATTR_PRIORITY: {
                    priority = nl_attr_get_be32(a);
                    break;
                }

                case OVS_KEY_ATTR_IN_PORT: {
                    ifindex = nl_attr_get_be32(a);
                    break;
                }

                case OVS_KEY_ATTR_ETHERTYPE: {
                    ovs_be16 etype_key = ntohs(nl_attr_get_be16(a));

                    if (ETH_TYPE_IPV6 == etype_key) {
                        table_type = NETDEV_SONIC_REDIS_ACL_TABLE_TYPE_L3V6;
                    }
                    break;
                }

                default: {
                    char namebuf[OVS_KEY_ATTR_STR_SIZE] = {0};
                    ovs_key_attr_to_string(attr_type, namebuf);
                }
            }
        }
    }

    /* when delete, must remove all fileds, but openflow does not specify action when deleting.
     * so here only specified ACE name, and hgetall the ACE to remove fields
     */
    if (INVALID_IFINDEX == ifindex) {
        VLOG_ERR("NOT handle the flow. Must specified in_port of flow.");
        return;
    } else {
        char ace_name_ar[REDIS_CMD_ACL_TABLE_NAME_LEN] = {0};
        char port_ar[REDIS_CMD_MAX_LENGTH] = {0};

        if (!netdev_sonic_port_name_by_number(ifindex, port_ar)) {
            VLOG_WARN("NOT handle the flow. Invalid in_port %d of flow.", ifindex);
            return;
        }

        dpif_sonic_construct_ace_name(ace_name_ar, port_ar, priority, table_type);
        VLOG_INFO("%s %d. %s.", __FUNCTION__, __LINE__, ace_name_ar);

        if (netdev_sonic_port_acl_set(ifindex, priority, table_type, false)) {
            char table_cmd_ar[REDIS_CMD_MAX_LENGTH] = {0};
            char table_ar[REDIS_CMD_MAX_LENGTH] = {0};
            dpif_sonic_construct_acl_table_name(table_ar, port_ar, table_type);

            sprintf(table_cmd_ar, "HDEL %s policy_desc ports@ stage type", table_ar);
            VLOG_INFO("%s %d. %s.", __FUNCTION__, __LINE__, table_cmd_ar);
            connectRedis(table_cmd_ar, ace_name_ar, REDIS_CMD_TYPE_REMOVE);
        } else {
            connectRedis(NULL, ace_name_ar, REDIS_CMD_TYPE_REMOVE);
        }

        /* update store after REDIS
         */
        netdev_sonic_port_priority_set(ifindex, priority, table_type, false);
    }
}

/* sonic supports match
 * in_port, ipv4, ethertype, L4 port, ip protocol, icmp type, vlan, tcp flag
 * NOT support MAC
 */
static void dpif_sonic_print_flow(const struct nlattr *key, size_t key_len,
        const struct nlattr *mask, size_t mask_len, const struct nlattr *actions, size_t actions_len)
{
    if ((0 == actions_len) || (0 == key_len)) {
        return;
    }

    if (0 != key_len) {
        const struct nlattr *a;
        unsigned int left;
        NL_ATTR_FOR_EACH (a, left, key, key_len) {
            int /*enum ovs_key_attr*/ attr_type = nl_attr_type(a);
            //ma is used to get mask value
            const struct nlattr *ma = (mask && mask_len
                           ? nl_attr_find__(mask, mask_len, attr_type) : NULL);

            if (mask && mask_len) {
                ma = nl_attr_find__(mask, mask_len, nl_attr_type(a));
            }

            switch (attr_type) {
                case OVS_KEY_ATTR_IN_PORT: {
                    bool is_exact = ma ? odp_mask_attr_is_exact(ma) : true;
                    int attr_mask = OVS_BE32_MAX;

                    if (!is_exact) {
                        attr_mask = nl_attr_get_be32(ma);
                    }

                    if (0 != attr_mask) {
                        VLOG_INFO("%s %d. inport:%u.", __FUNCTION__, __LINE__, nl_attr_get_be32(a));
                        VLOG_INFO("%s %d. mask:%x.", __FUNCTION__, __LINE__, nl_attr_get_be32(ma));
                    }
                    break;
                }

                /*
                case OVS_KEY_ATTR_ETHERNET: {
                    const struct ovs_key_ethernet *attrmask = ma ? nl_attr_get(ma) : NULL;
                    const struct ovs_key_ethernet *attrkey = nl_attr_get(a);
                    const struct eth_addr src_key = attrkey->eth_src;
                    const struct eth_addr dst_key = attrkey->eth_dst;
                    const struct eth_addr *src_mask = MASK(attrmask, eth_src);
                    const struct eth_addr *dst_mask = MASK(attrmask, eth_dst);

                    if (src_mask && !eth_addr_is_zero(*src_mask)) {
                        VLOG_INFO("%s %d. SA:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(src_key));
                        VLOG_INFO("%s %d. SA mask:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(*src_mask));
                    }

                    if (dst_mask && !eth_addr_is_zero(*dst_mask)) {
                        VLOG_INFO("%s %d. DA:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(dst_key));
                        VLOG_INFO("%s %d. DA mask:"ETH_ADDR_FMT".", __FUNCTION__, __LINE__, ETH_ADDR_ARGS(*dst_mask));
                    }
                    break;
                }
                */

                case OVS_KEY_ATTR_VLAN: {
                    ovs_be16 tci = nl_attr_get_be16(a);
                    ovs_be16 tci_mask = (ma ? nl_attr_get_be16(ma) : OVS_BE16_MAX);

                    if (0 != vlan_tci_to_vid(tci_mask)) {
                        VLOG_INFO("%s %d. vid:%u.", __FUNCTION__, __LINE__, vlan_tci_to_vid(tci));
                        VLOG_INFO("%s %d. mask:%x.", __FUNCTION__, __LINE__, vlan_tci_to_vid(tci_mask));
                    }
                    if (0 != vlan_tci_to_pcp(tci_mask)) {
                        VLOG_INFO("%s %d. vlan pcp:%u.", __FUNCTION__, __LINE__, vlan_tci_to_pcp(tci));
                        VLOG_INFO("%s %d. mask:%x.", __FUNCTION__, __LINE__, vlan_tci_to_pcp(tci_mask));
                    }
                    break;
                }

                case OVS_KEY_ATTR_ETHERTYPE: {
                    if (ma && (0 != nl_attr_get_be16(ma))) {
                        VLOG_INFO("%s %d. etype:%u.", __FUNCTION__, __LINE__, ntohs(nl_attr_get_be16(a)));
                        VLOG_INFO("%s %d. mask:%x.", __FUNCTION__, __LINE__, ntohs(nl_attr_get_be16(ma)));
                    }
                    break;
                }

                case OVS_KEY_ATTR_IPV4: {
                    const struct ovs_key_ipv4 *attrkey = nl_attr_get(a);
                    const struct ovs_key_ipv4 *attrmask = ma ? nl_attr_get(ma) : NULL;
                    ovs_be32 src_key = attrkey->ipv4_src;
                    ovs_be32 dst_key = attrkey->ipv4_dst;
                    uint8_t proto = attrkey->ipv4_proto;
                    uint8_t tos = attrkey->ipv4_tos;
                    uint8_t ttl = attrkey->ipv4_ttl;
                    uint8_t frag = attrkey->ipv4_frag;
                    const ovs_be32 *src_mask = MASK(attrmask, ipv4_src);
                    const ovs_be32 *dst_mask = MASK(attrmask, ipv4_dst);
                    const uint8_t *proto_mask = MASK(attrmask, ipv4_proto);
                    const uint8_t *tos_mask = MASK(attrmask, ipv4_tos);
                    const uint8_t *ttl_mask = MASK(attrmask, ipv4_ttl);
                    const uint8_t *frag_mask = MASK(attrmask, ipv4_frag);

                    if (src_mask && (0 != *src_mask)) {
                        VLOG_INFO("%s %d. SIP:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(src_key));
                        VLOG_INFO("%s %d. SIP mask:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(*src_mask));
                    }
                    if (dst_mask && (0 != *dst_mask)) {
                        VLOG_INFO("%s %d. DIP:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(dst_key));
                        VLOG_INFO("%s %d. DIP mask:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(*dst_mask));
                    }
                    if (proto_mask && (0 != *proto_mask)) {
                        VLOG_INFO("%s %d. IP protocol:%d.", __FUNCTION__, __LINE__, proto);
                        VLOG_INFO("%s %d. IP protocol mask:%X.", __FUNCTION__, __LINE__, *proto_mask);
                    }
                    if (tos_mask && (0 != *tos_mask)) {
                        VLOG_INFO("%s %d. IP tos:%d.", __FUNCTION__, __LINE__, tos);
                        VLOG_INFO("%s %d. IP tos mask:%X.", __FUNCTION__, __LINE__, *tos_mask);
                    }
                    if (ttl_mask && (0 != *ttl_mask)) {
                        VLOG_INFO("%s %d. IP TTL:%d.", __FUNCTION__, __LINE__, ttl);
                        VLOG_INFO("%s %d. IP TTL mask:%X.", __FUNCTION__, __LINE__, *ttl_mask);
                    }
                    if (frag_mask && (0 != *frag_mask)) {
                        VLOG_INFO("%s %d. IP frag:%d.", __FUNCTION__, __LINE__, frag);
                        VLOG_INFO("%s %d. IP frag mask:%X.", __FUNCTION__, __LINE__, *frag_mask);
                    }
                    break;
                }

                case OVS_KEY_ATTR_TCP:
                case OVS_KEY_ATTR_UDP:
                case OVS_KEY_ATTR_SCTP: {
                    const struct ovs_key_tcp *attrkey = nl_attr_get(a);
                    const struct ovs_key_tcp *attrmask = ma ? nl_attr_get(ma) : NULL;
                    ovs_be16 src_key = attrkey->tcp_src;
                    ovs_be16 dst_key = attrkey->tcp_dst;
                    const ovs_be16 *src_mask = MASK(attrmask, tcp_src);
                    const ovs_be16 *dst_mask = MASK(attrmask, tcp_dst);

                    if (src_mask && (0 != *src_mask)) {
                        VLOG_INFO("%s %d. TCP src:%d.", __FUNCTION__, __LINE__, ntohs(src_key));
                        VLOG_INFO("%s %d. TCP src mask:%X.", __FUNCTION__, __LINE__, ntohs(*src_mask));
                    }
                    if (dst_mask && (0 != *dst_mask)) {
                        VLOG_INFO("%s %d. TCP dst:%d.", __FUNCTION__, __LINE__, ntohs(dst_key));
                        VLOG_INFO("%s %d. TCP dst mask:%X.", __FUNCTION__, __LINE__, ntohs(*dst_mask));
                    }
                    break;
                }

                case OVS_KEY_ATTR_TCP_FLAGS: {
                    if (ma && (0 != nl_attr_get_be16(ma))) {
                        VLOG_INFO("%s %d. TCP flags:%u.", __FUNCTION__, __LINE__, ntohs(nl_attr_get_be16(a)));
                        VLOG_INFO("%s %d. TCP flags mask:%x.", __FUNCTION__, __LINE__, ntohs(nl_attr_get_be16(ma)));
                    }
                    break;
                }

                case OVS_KEY_ATTR_ICMP: {
                    const struct ovs_key_icmp *attrkey = nl_attr_get(a);
                    const struct ovs_key_icmp *attrmask = ma ? nl_attr_get(ma) : NULL;
                    uint8_t type_key = attrkey->icmp_type;
                    uint8_t code_key = attrkey->icmp_code;
                    const uint8_t *type_mask = MASK(attrmask, icmp_type);
                    const uint8_t *code_mask = MASK(attrmask, icmp_code);

                    if (type_mask && (0 != *type_mask)) {
                        VLOG_INFO("%s %d. ICMP type:%d.", __FUNCTION__, __LINE__, ntohs(type_key));
                        VLOG_INFO("%s %d. ICMP type mask:%X.", __FUNCTION__, __LINE__, ntohs(*type_mask));
                    }
                    if (code_mask && (0 != *code_mask)) {
                        VLOG_INFO("%s %d. ICMP code:%d.", __FUNCTION__, __LINE__, ntohs(code_key));
                        VLOG_INFO("%s %d. ICMP code mask:%X.", __FUNCTION__, __LINE__, ntohs(*code_mask));
                    }
                    break;
                }

                default: {
                    char namebuf[OVS_KEY_ATTR_STR_SIZE] = {0};
                    ovs_key_attr_to_string(attr_type, namebuf);
                }
            }
        }
    }

    if (0 != actions_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
            int type = nl_attr_type(a);
            int expected_len = odp_action_len(nl_attr_type(a));

            if ((expected_len != ATTR_LEN_VARIABLE) && (nl_attr_get_size(a) != expected_len)) {
                VLOG_INFO("%s %d. bad length:expect %ld for:%d", __FUNCTION__, __LINE__, nl_attr_get_size(a), expected_len);
                return;
            }

            switch (type) {
                case OVS_ACTION_ATTR_OUTPUT:
                    VLOG_INFO("%s %d. OVS_ACTION_ATTR_OUTPUT %u.", __FUNCTION__, __LINE__, nl_attr_get_u32(a));
                    break;
                case OVS_ACTION_ATTR_DROP:
                    VLOG_INFO("%s %d. OVS_ACTION_ATTR_DROP", __FUNCTION__, __LINE__);
                    break;

                default:
                    VLOG_INFO("%s %d. not handle %d.", __FUNCTION__, __LINE__, type);
                    break;
            }
        }
    }
}

/* arguments
 * cmd_p: command string for config DB; ACE name when removed
 * table_p: ACL table name
 * type: REDIS_CMD_TYPE_XXX
 */
static void connectRedis(char *table_cmd_p, char *cmd_p, int type)
{
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisReply *reply;
    redisContext *c;

    c = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if (c->err) {
        VLOG_INFO("%s %d. error: %s.", __FUNCTION__, __LINE__, c->errstr);
        if (c) {
            redisFree(c);
        }
        return;
    }
    VLOG_INFO("connection OK\n");

    /* enter config DB */
    reply = redisCommand(c,"select 4");
    VLOG_INFO("select 4:%s\n", reply->str);
    freeReplyObject(reply);

    if (REDIS_CMD_TYPE_ADD == type) {
        if (NULL != table_cmd_p) { /* need to create ACL table */
            reply = redisCommand(c, table_cmd_p);
            if (NULL != reply) {
                if (REDIS_REPLY_ERROR == reply->type) {
                    VLOG_ERR("Failed cmd: %s error:%s", table_cmd_p, reply->str);
                } else {
                    VLOG_INFO("OK: %s", table_cmd_p);
                }
            }
            freeReplyObject(reply);
        }

        reply = redisCommand(c, cmd_p);
        if (NULL != reply) {
            if (REDIS_REPLY_ERROR == reply->type) {
                VLOG_ERR("Failed cmd: %s error:%s", cmd_p, reply->str);
            } else {
                VLOG_INFO("OK: %s", cmd_p);
            }
        }
        freeReplyObject(reply);
    } else {
        /* remove: get all fileds to remove
         */
        char send_cmd_ar[REDIS_CMD_MAX_LENGTH] = {0};
        sprintf(send_cmd_ar, "hgetall %s", cmd_p);
        reply = redisCommand(c, send_cmd_ar);

        if (REDIS_REPLY_ERROR == reply->type) {
            VLOG_ERR("hgetall %s REDIS_REPLY_ERROR:%s", cmd_p, reply->str);
        } else if (REDIS_REPLY_ARRAY != reply->type) {
            VLOG_ERR("hgetall %s ! REDIS_REPLY_ARRAY:%d", cmd_p, reply->type);
        } else {
            int i = 0;
            memset(send_cmd_ar, 0, sizeof(send_cmd_ar));
            sprintf(send_cmd_ar, "hdel %s", cmd_p);

            for (i = 0; i < reply->elements; ++i) {
                if (0 == (i%2)) {
                    strcat(send_cmd_ar, " ");
                    strcat(send_cmd_ar, reply->element[i]->str);
                }
            }VLOG_INFO("send_cmd_ar: %s", send_cmd_ar);
            freeReplyObject(reply);

            reply = redisCommand(c, send_cmd_ar);
            if (NULL != reply) {
                if (REDIS_REPLY_ERROR == reply->type) {
                    VLOG_ERR("Failed cmd: %s error:%s", send_cmd_ar, reply->str);
                } else {
                    VLOG_INFO("OK: %s", send_cmd_ar);
                }
            }
            freeReplyObject(reply);
        }

        if (NULL != table_cmd_p) { /* remove table after removing ACE */
            reply = redisCommand(c, table_cmd_p);
            if (NULL != reply) {
                if (REDIS_REPLY_ERROR == reply->type) {
                    VLOG_ERR("Failed cmd: %s error:%s\n", table_cmd_p, reply->str);
                } else {
                    VLOG_INFO("OK: %s\n", table_cmd_p);
                }
            }
            freeReplyObject(reply);
        }
    }

   redisFree(c);
}
