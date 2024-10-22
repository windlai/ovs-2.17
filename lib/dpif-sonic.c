
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
static void dpif_sonic_print_flow(const struct nlattr *key, size_t key_len,
        const struct nlattr *mask, size_t mask_len, const struct nlattr *actions, size_t actions_len);


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
 * Initialized by dpif_sonic_init(). */
static int ovs_datapath_family;
static int ovs_flow_family;
static int ovs_packet_family;
static int ovs_meter_family;



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
        struct dpif_flow_get *get;

        switch (op->type) {
            case DPIF_OP_FLOW_PUT: {
                put = &op->flow_put;
                dpif_sonic_print_flow(put->key, put->key_len,
                        put->mask, put->mask_len, put->actions, put->actions_len);
                break;
            }

            case DPIF_OP_FLOW_DEL: {
                del = &op->flow_del;
                break;
            }

            case DPIF_OP_FLOW_GET: {
                get = &op->flow_get;
                break;
            }
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

static void dpif_sonic_print_flow(const struct nlattr *key, size_t key_len,
        const struct nlattr *mask, size_t mask_len, const struct nlattr *actions, size_t actions_len) {
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
                    int mask = 0;

                    if (!is_exact) {
                        mask = nl_attr_get_be32(ma);
                    }

                    if (0 != mask) {
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
                    bool src_mask_full = !src_mask || eth_mask_is_exact(*src_mask);
                    bool dst_mask_full = !dst_mask || eth_mask_is_exact(*dst_mask);

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

                case OVS_KEY_ATTR_IPV4: {
                    const struct ovs_key_ipv4 *attrkey = nl_attr_get(a);
                    const struct ovs_key_ipv4 *attrmask = ma ? nl_attr_get(ma) : NULL;
                    ovs_be32 src_key = attrkey->ipv4_src;
                    ovs_be32 dst_key = attrkey->ipv4_dst;
                    const ovs_be32 *src_mask = MASK(attrmask, ipv4_src);
                    const ovs_be32 *dst_mask = MASK(attrmask, ipv4_dst);
                    bool src_mask_full = !src_mask || *src_mask == OVS_BE32_MAX;
                    bool dst_mask_full = !dst_mask || *dst_mask == OVS_BE32_MAX;

                    if (src_mask && (0 != *src_mask)) {
                        VLOG_INFO("%s %d. SIP:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(src_key));
                        VLOG_INFO("%s %d. SIP mask:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(*src_mask));
                    }
                    if (dst_mask && (0 != *dst_mask)) {
                        VLOG_INFO("%s %d. DIP:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(dst_key));
                        VLOG_INFO("%s %d. DIP mask:"IP_FMT".", __FUNCTION__, __LINE__, IP_ARGS(*dst_mask));
                    }
                    break;
                }

                default:
                    char namebuf[OVS_KEY_ATTR_STR_SIZE] = {0};
                    ovs_key_attr_to_string(attr_type, namebuf);
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
    } else {
        VLOG_INFO("%s %d. actions_len = 0, drop ???", __FUNCTION__, __LINE__);
    }
}