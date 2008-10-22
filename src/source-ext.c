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

/* hooks */
static pa_hook_result_t source_put(void *, void *, void *);
static pa_hook_result_t source_unlink(void *, void *, void *);

static void send_device_state(struct userdata *, const char *, char *);


struct pa_source_evsubscr *pa_source_ext_subscription(struct userdata *u)
{
    pa_core                   *core;
    pa_hook                   *hooks;
    struct pa_source_evsubscr *subscr;
    pa_hook_slot              *put;
    pa_hook_slot              *unlink;
    
    pa_assert(u);
    pa_assert((core = u->core));

    hooks  = core->hooks;
    
    put    = pa_hook_connect(hooks + PA_CORE_HOOK_SOURCE_PUT,
                             PA_HOOK_LATE, source_put, (void *)u);
    unlink = pa_hook_connect(hooks + PA_CORE_HOOK_SOURCE_UNLINK,
                             PA_HOOK_LATE, source_unlink, (void *)u);


    subscr = pa_xnew0(struct pa_source_evsubscr, 1);
    
    subscr->put    = put;
    subscr->unlink = unlink;
    
    return subscr;
}

void pa_source_ext_subscription_free(struct pa_source_evsubscr *subscr)
{
    if (subscr != NULL) {
        pa_hook_slot_free(subscr->put);
        pa_hook_slot_free(subscr->unlink);

        pa_xfree(subscr);
    }
}

char *pa_source_ext_get_name(struct pa_source *source)
{
    return source->name ? source->name : (char *)"<unknown>";
}

int pa_source_ext_set_mute(struct userdata *u, char *type, int mute)
{
    void              *state = NULL;
    pa_idxset         *idxset;
    struct pa_source  *source;
    char              *name;

    pa_assert(u);
    pa_assert(type);
    pa_assert(u->core);
    pa_assert((idxset = u->core->sources));

    while ((source = pa_idxset_iterate(idxset, &state, NULL)) != NULL) {
        if ((name = pa_source_ext_get_name(source)) != NULL) {

            if (pa_classify_is_source_typeof(u, name, type)) {
                pa_log_debug("%s() %smute source '%s' type '%s'",
                             __FUNCTION__, mute ? "" : "un", name, type);

                pa_source_set_mute(source, mute);

                return 0;
            }
        }
    }


    return -1;
}


static pa_hook_result_t source_put(void *hook_data, void *call_data,
                                       void *slot_data)
{
    struct pa_source  *source = (struct pa_source *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;
    char            *name;
    uint32_t         idx;
    char             buf[1024];
    int              ret;

    if (source && u) {
        name = pa_source_ext_get_name(source);
        idx  = source->index;

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
                pa_log_debug("new source '%s' (idx=%d type %s)",
                             name, idx, buf);
#if 0
                pa_policy_groupset_update_default_source(u, PA_IDXSET_INVALID);
#endif
                pa_policy_groupset_register_source(u, source);
                send_device_state(u, PA_POLICY_CONNECTED, buf);
            }
        }
    }

    return PA_HOOK_OK;
}


static pa_hook_result_t source_unlink(void *hook_data, void *call_data,
                                          void *slot_data)
{
    struct pa_source  *source = (struct pa_source *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;
    char            *name;
    uint32_t         idx;
    char             buf[1024];
    int              ret;

    if (source && u) {
        name = pa_source_ext_get_name(source);
        idx  = source->index;

        if (pa_classify_source(u, idx, NULL, buf, sizeof(buf)) <= 0)
            pa_log_debug("remove source '%s' (idx=%d)", name, idx);
        else {
            pa_log_debug("remove source '%s' (idx=%d, type=%s)", name,idx,buf);
            
#if 0
            pa_policy_groupset_update_default_source(u, idx);
#endif
            pa_policy_groupset_unregister_source(u, idx);
            send_device_state(u, PA_POLICY_DISCONNECTED, buf);
        }
    }

    return PA_HOOK_OK;
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
