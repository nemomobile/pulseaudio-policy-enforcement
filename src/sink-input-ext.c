#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <pulsecore/pulsecore-config.h>

#include <pulse/def.h>
#include <pulse/proplist.h>
#include <pulse/volume.h>
#include <pulsecore/sink.h>
#include <pulsecore/sink-input.h>

#include "policy-group.h"
#include "sink-input-ext.h"
#include "classify.h"

/* hooks */
static pa_hook_result_t sink_input_put(void *, void *, void *);
static pa_hook_result_t sink_input_unlink(void *, void *, void *);

static void handle_new_sink_input(struct userdata *, struct pa_sink_input *);
static void handle_removed_sink_input(struct userdata *,
                                      struct pa_sink_input *);

struct pa_sinp_evsubscr *pa_sink_input_ext_subscription(struct userdata *u)
{
    pa_core                 *core;
    pa_hook                 *hooks;
    struct pa_sinp_evsubscr *subscr;
    pa_hook_slot            *put;
    pa_hook_slot            *unlink;
    
    pa_assert(u);
    pa_assert_se((core = u->core));

    hooks  = core->hooks;
    
    put    = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_INPUT_PUT,
                             PA_HOOK_LATE, sink_input_put, (void *)u);
    unlink = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_INPUT_UNLINK,
                             PA_HOOK_LATE, sink_input_unlink, (void *)u);


    subscr = pa_xnew0(struct pa_sinp_evsubscr, 1);
    
    subscr->put    = put;
    subscr->unlink = unlink;

    return subscr;
}

void  pa_sink_input_ext_subscription_free(struct pa_sinp_evsubscr *subscr)
{
    if (subscr != NULL) {
        pa_hook_slot_free(subscr->put);
        pa_hook_slot_free(subscr->unlink);
        
        pa_xfree(subscr);
    }
}

void pa_sink_input_ext_discover(struct userdata *u)
{
    void                 *state = NULL;
    pa_idxset            *idxset;
    struct pa_sink_input *sinp;

    pa_assert(u);
    pa_assert(u->core);
    pa_assert_se((idxset = u->core->sink_inputs));

    while ((sinp = pa_idxset_iterate(idxset, &state, NULL)) != NULL)
        handle_new_sink_input(u, sinp);
}


int pa_sink_input_ext_set_policy_group(struct pa_sink_input *sinp,
                                         char *group)
{
    int ret;

    assert(sinp);

    if (group) 
        ret = pa_proplist_sets(sinp->proplist, PA_PROP_POLICY_GROUP, group);
    else
        ret = pa_proplist_unset(sinp->proplist, PA_PROP_POLICY_GROUP);

    return ret;
}

char *pa_sink_input_ext_get_policy_group(struct pa_sink_input *sinp)
{
    const char *group;

    assert(sinp);

    group = pa_proplist_gets(sinp->proplist, PA_PROP_POLICY_GROUP);

    if (group == NULL)
        group = PA_POLICY_DEFAULT_GROUP_NAME;

    return (char *)group;
}

char *pa_sink_input_ext_get_name(struct pa_sink_input *sinp)
{
    const char *name;

    assert(sinp);

    name = pa_proplist_gets(sinp->proplist, PA_PROP_MEDIA_NAME);

    if (name == NULL)
        name = "<unknown>";
    
    return (char *)name;
}


int pa_sink_input_ext_set_volume_limit(struct pa_sink_input *sinp,
                                       pa_volume_t limit)
{
    pa_sink    *sink;
    pa_cvolume *vol;
    int         i;

    pa_assert(sinp);
    pa_assert_se((sink = sinp->sink));

    if (limit == 0)
        pa_sink_input_set_mute(sinp, TRUE, TRUE);
    else {
        pa_sink_input_set_mute(sinp, FALSE, TRUE);

        if (limit > PA_VOLUME_NORM)
            limit = PA_VOLUME_NORM;

        vol = pa_xnewdup(struct pa_cvolume, &sinp->virtual_volume, 1);
        
        pa_assert(vol->channels <= PA_CHANNELS_MAX);
        
        for (i = 0;  i < vol->channels;  i++) {
            if (vol->values[i] > limit)
                vol->values[i] = limit;
        }
        
        pa_sink_input_set_volume(sinp, vol, TRUE);
    }

    return 0;
}


 
static pa_hook_result_t sink_input_put(void *hook_data, void *call_data,
                                       void *slot_data)
{
    struct pa_sink_input *sinp = (struct pa_sink_input *)call_data;
    struct userdata      *u    = (struct userdata *)slot_data;

    handle_new_sink_input(u, sinp);

    return PA_HOOK_OK;
}


static pa_hook_result_t sink_input_unlink(void *hook_data, void *call_data,
                                          void *slot_data)
{
    struct pa_sink_input *sinp = (struct pa_sink_input *)call_data;
    struct userdata      *u    = (struct userdata *)slot_data;

    handle_removed_sink_input(u, sinp);

    return PA_HOOK_OK;
}

static void handle_new_sink_input(struct userdata      *u,
                                  struct pa_sink_input *sinp)
{
    char *snam;
    char *gnam;

    if (sinp && u) {
        snam = pa_sink_input_ext_get_name(sinp);
        gnam = pa_classify_sink_input(u, sinp);

        pa_policy_group_insert_sink_input(u, gnam, sinp);

        pa_log_debug("new sink_input %s (idx=%d) (group=%s)",
                     snam, sinp->index, gnam);
    }
}


static void handle_removed_sink_input(struct userdata      *u,
                                      struct pa_sink_input *sinp)
{
    char *snam;
    char *gnam;

    if (sinp && u) {
        snam = pa_sink_input_ext_get_name(sinp);
        gnam = pa_classify_sink_input(u, sinp);

        pa_policy_group_remove_sink_input(u, sinp->index);

        pa_log_debug("removed sink_input %s (idx=%d) (group=%s)",
                     snam, sinp->index, gnam);
    }
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
