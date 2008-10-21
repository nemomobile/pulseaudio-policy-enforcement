#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/def.h>
#include <pulsecore/source.h>

#include "source-ext.h"
#include "classify.h"
#include "policy-group.h"
#include "dbusif.h"

static void handle_source_events(pa_core *, pa_subscription_event_type_t,
				 uint32_t, void *);
static void send_device_state(struct userdata *, const char *, char *);


pa_subscription *pa_source_ext_subscription(struct userdata *u)
{
    pa_subscription *subscr;
    
    pa_assert(u->core);
    
    subscr = pa_subscription_new(u->core, 1<<PA_SUBSCRIPTION_EVENT_SOURCE,
                                 handle_source_events, (void *)u);
    
    return subscr;
}

char *pa_source_ext_get_name(struct pa_source *source)
{
    return source->name ? source->name : (char *)"<unknown>";
}


static void handle_source_events(pa_core *c,pa_subscription_event_type_t t,
                               uint32_t idx, void *userdata)
{
    struct userdata    *u  = userdata;
    uint32_t            et = t & PA_SUBSCRIPTION_EVENT_TYPE_MASK;
    struct pa_source   *source;
    char               *name;
    char                buf[1024];
    int                 ret;

    pa_assert(u);
    
    switch (et) {

    case PA_SUBSCRIPTION_EVENT_NEW:
        if ((source = pa_idxset_get_by_index(c->sources, idx)) != NULL) {
            name = pa_source_ext_get_name(source);

            if (pa_classify_source(u, idx, name, buf, sizeof(buf)) <= 0)
                pa_log_debug("new source '%s' (idx=%d)", name, idx);
            else {
                ret = pa_proplist_sets(source->proplist,
                                       PA_PROP_POLICY_DEVTYPELIST, buf);

                if (ret < 0) {
                    pa_log("failed to set property '%s' on source '%s'",
                           PA_PROP_POLICY_DEVTYPELIST, name);
                }
                else {
                    pa_log_debug("new source '%s' (idx=%d) (type %s)",
                                 name, idx, buf);

#if 0
                    pa_policy_groupset_update_default_source(u,
                                                             PA_IDXSET_INVALID
                                                             );
#endif
                    pa_policy_groupset_register_source(u, source);

                    send_device_state(u, PA_POLICY_CONNECTED, buf);
                }
            }
        }
        break;
        
    case PA_SUBSCRIPTION_EVENT_CHANGE:
        break;        
        
    case PA_SUBSCRIPTION_EVENT_REMOVE:
        if (pa_classify_source(u, idx, NULL, buf, sizeof(buf)) <= 0)
            pa_log_debug("remove source (idx=%d)", idx);
        else {
            pa_log_debug("remove source %d (type=%s)", idx, buf);
            
#if 0
            pa_policy_groupset_update_default_source(u, idx);
#endif
            pa_policy_groupset_unregister_source(u, idx);

            send_device_state(u, PA_POLICY_DISCONNECTED, buf);
        }
        break;

    default:
        pa_log("unknown source event type %d", et);
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

    if (typelist && typelist[0]) {
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
    }

#undef MAX_TYPE
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
