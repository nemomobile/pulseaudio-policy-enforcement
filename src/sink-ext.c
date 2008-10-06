#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/def.h>
#include <pulsecore/sink.h>

#include "sink-ext.h"
#include "classify.h"
#include "policy-group.h"
#include "dbusif.h"

static void handle_sink_events(pa_core *, pa_subscription_event_type_t,
                               uint32_t, void *);
static void send_device_state(struct userdata *, const char *, char *);


pa_subscription *pa_sink_ext_subscription(struct userdata *u)
{
    pa_subscription *subscr;
    
    pa_assert(u->core);
    
    subscr = pa_subscription_new(u->core, 1<<PA_SUBSCRIPTION_EVENT_SINK,
                                 handle_sink_events, (void *)u);
    
    return subscr;
}

char *pa_sink_ext_get_name(struct pa_sink *sink)
{
    return sink->name ? sink->name : (char *)"<unknown>";
}


static void handle_sink_events(pa_core *c,pa_subscription_event_type_t t,
                               uint32_t idx, void *userdata)
{
    struct userdata    *u = userdata;
    uint32_t            et    = t & PA_SUBSCRIPTION_EVENT_TYPE_MASK;
    struct pa_sink     *sink;
    char               *name;
    char                buf[1024];
    int                 ret;

    pa_assert(u);
    
    switch (et) {

    case PA_SUBSCRIPTION_EVENT_NEW:
        if ((sink = pa_idxset_get_by_index(c->sinks, idx)) != NULL) {
            name = pa_sink_ext_get_name(sink);

            if (pa_classify_sink(u, idx, name, buf, sizeof(buf)) <= 0)
                pa_log_debug("new sink '%s' (idx=%d)", name, idx);
            else {
                ret = pa_proplist_sets(sink->proplist,
                                       PA_PROP_POLICY_DEVTYPELIST, buf);

                if (ret < 0) {
                    pa_log("failed to set property '%s' on sink '%s'",
                           PA_PROP_POLICY_DEVTYPELIST, name);
                }
                else {
                    pa_log_debug("new sink '%s' (idx=%d) (type %s)",
                                 name, idx, buf);
                    pa_policy_groupset_update_default_sink(u,PA_IDXSET_INVALID);
                    send_device_state(u, "1", buf);
                }
            }
        }
        break;
        
    case PA_SUBSCRIPTION_EVENT_CHANGE:
        break;        
        
    case PA_SUBSCRIPTION_EVENT_REMOVE:
        if (pa_classify_sink(u, idx, NULL, buf, sizeof(buf)) <= 0)
            pa_log_debug("remove sink (idx=%d)", idx);
        else {
            pa_log_debug("remove sink %d (type=%s)", idx, buf);
            
            pa_policy_groupset_update_default_sink(u, idx);

            send_device_state(u, "0", buf);
        }
        break;

    default:
        pa_log("unknown sink event type %d", et);
        break;
    }
}

static void send_device_state(struct userdata *u, const char *state,
                              char *typelist) 
{
#define MAX_TYPE 256

    char *types[MAX_TYPE];
    int   ntype;
    char  buf[1024];
    char *p, *q, c;

    ntype = 0;

    p = typelist - 1;
    q = buf;

    do {
        p++;

        if (ntype < MAX_TYPE)
            types[ntype] = q;
        else {
            pa_log("%s() list overflow", __FUNCTION__);
            return;
        }

        while ((c = *p) != ' ' && c != '\0') {
            if (q < buf + sizeof(buf)-1)
                *q++ = *p++;
            else {
                pa_log("%s() buffer overflow", __FUNCTION__);
                return;
            }
        }
        *q++ = '\0';
        ntype++;
        
    } while (*p);

    pa_policy_dbusif_send_device_state(u, (char *)state, types, ntype);

#undef MAX_TYPE
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
