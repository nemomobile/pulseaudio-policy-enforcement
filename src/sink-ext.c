#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <pulsecore/pulsecore-config.h>

#include <pulse/def.h>
#include <pulsecore/sink.h>

#include "sink-ext.h"
#include "classify.h"
#include "policy-group.h"
#include "dbusif.h"

/* hooks */
static pa_hook_result_t sink_put(void *, void *, void *);
static pa_hook_result_t sink_unlink(void *, void *, void *);

static void handle_new_sink(struct userdata *, struct pa_sink *);
static void handle_removed_sink(struct userdata *, struct pa_sink *);


struct pa_sink_evsubscr *pa_sink_ext_subscription(struct userdata *u)
{
    pa_core                 *core;
    pa_hook                 *hooks;
    struct pa_sink_evsubscr *subscr;
    pa_hook_slot            *put;
    pa_hook_slot            *unlink;
    
    pa_assert(u);
    pa_assert_se((core = u->core));

    hooks  = core->hooks;
    
    put    = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_PUT,
                             PA_HOOK_LATE, sink_put, (void *)u);
    unlink = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_UNLINK,
                             PA_HOOK_LATE, sink_unlink, (void *)u);
    

    subscr = pa_xnew0(struct pa_sink_evsubscr, 1);
    
    subscr->put    = put;
    subscr->unlink = unlink;

    return subscr;
}

void  pa_sink_ext_subscription_free(struct pa_sink_evsubscr *subscr)
{
    if (subscr != NULL) {
        pa_hook_slot_free(subscr->put);
        pa_hook_slot_free(subscr->unlink);

        pa_xfree(subscr);
    }
}

void pa_sink_ext_discover(struct userdata *u)
{
    void            *state = NULL;
    pa_idxset       *idxset;
    struct pa_sink  *sink;

    pa_assert(u);
    pa_assert(u->core);
    pa_assert_se((idxset = u->core->sinks));

    while ((sink = pa_idxset_iterate(idxset, &state, NULL)) != NULL)
        handle_new_sink(u, sink);
}


char *pa_sink_ext_get_name(struct pa_sink *sink)
{
    return sink->name ? sink->name : (char *)"<unknown>";
}

static pa_hook_result_t sink_put(void *hook_data, void *call_data,
                                 void *slot_data)
{
    struct pa_sink  *sink = (struct pa_sink *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;

    handle_new_sink(u, sink);

    return PA_HOOK_OK;
}


static pa_hook_result_t sink_unlink(void *hook_data, void *call_data,
                                    void *slot_data)
{
    struct pa_sink  *sink = (struct pa_sink *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;

    handle_removed_sink(u, sink);

    return PA_HOOK_OK;
}


static void handle_new_sink(struct userdata *u, struct pa_sink *sink)
{
    char     *name;
    uint32_t  idx;
    char      buf[1024];
    int       len;
    int       ret;

    if (sink && u) {
        name = pa_sink_ext_get_name(sink);
        idx  = sink->index;
        len  = pa_classify_sink(u, sink, 0,0, buf, sizeof(buf));

        if (len <= 0)
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

                pa_policy_groupset_update_default_sink(u, PA_IDXSET_INVALID);
                pa_policy_groupset_register_sink(u, sink);

                len = pa_classify_sink(u, sink, PA_POLICY_DISABLE_NOTIFY,0,
                                       buf, sizeof(buf));
                if (len > 0) {
                    pa_policy_send_device_state(u, PA_POLICY_CONNECTED, buf);
                }
            }
        }
    }
}

static void handle_removed_sink(struct userdata *u, struct pa_sink *sink)
{
    char            *name;
    uint32_t         idx;
    char             buf[1024];
    int              len;

    if (sink && u) {
        name = pa_sink_ext_get_name(sink);
        idx  = sink->index;
        len  = pa_classify_sink(u, sink, 0,0, buf, sizeof(buf));

        if (len <= 0)
            pa_log_debug("remove sink '%s' (idx=%d)", name, idx);
        else {
            pa_log_debug("remove sink '%s' (idx=%d, type=%s)", name,idx, buf);
            
            pa_policy_groupset_update_default_sink(u, idx);
            pa_policy_groupset_unregister_sink(u, idx);

            len = pa_classify_sink(u, sink, PA_POLICY_DISABLE_NOTIFY,0,
                                   buf, sizeof(buf));
            
            if (len > 0) {
                pa_policy_send_device_state(u, PA_POLICY_DISCONNECTED, buf);
            }
        }
    }
}


void pa_policy_send_device_state(struct userdata *u, const char *state,
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
