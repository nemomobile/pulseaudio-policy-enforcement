#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/def.h>
#include <pulse/proplist.h>
#include <pulsecore/sink.h>
#include <pulsecore/sink-input.h>

#include "policy-group.h"
#include "sink-input-ext.h"
#include "classify.h"



static void handle_sink_input_events(pa_core *, pa_subscription_event_type_t,
				     uint32_t, void *);



pa_subscription *pa_sink_input_ext_subscription(struct userdata *u)
{
    pa_subscription *subscr;
    
    pa_assert(u->core);
    
    subscr = pa_subscription_new(u->core, 1<<PA_SUBSCRIPTION_EVENT_SINK_INPUT,
                                 handle_sink_input_events, (void *)u);
    
    return subscr;
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
    pa_cvolume vol;
    int        i;

    pa_assert(sinp);

    if (limit > PA_VOLUME_NORM)
        limit = PA_VOLUME_NORM;

    vol = sinp->volume;

    pa_assert(vol.channels <= PA_CHANNELS_MAX);

    for (i = 0;  i < vol.channels;  i++) {
        if (vol.values[i] > limit)
            vol.values[i] = limit;
    }

    pa_asyncmsgq_post(sinp->sink->asyncmsgq, PA_MSGOBJECT(sinp),
                      PA_SINK_INPUT_MESSAGE_SET_VOLUME,
                      pa_xnewdup(struct pa_cvolume,&vol,1), 0, NULL, pa_xfree);

    return 0;
}


static void handle_sink_input_events(pa_core *c,pa_subscription_event_type_t t,
				     uint32_t idx, void *userdata)
{
    struct userdata      *u  = userdata;
    uint32_t              et = t & PA_SUBSCRIPTION_EVENT_TYPE_MASK;
    struct pa_sink_input *sinp;
    char                 *snam;
    char                 *gnam;
    
    pa_assert(u);
    
    switch (et) {

    case PA_SUBSCRIPTION_EVENT_NEW:
        if ((sinp = pa_idxset_get_by_index(c->sink_inputs, idx)) != NULL) {
            snam = pa_sink_input_ext_get_name(sinp);
            gnam = pa_classify_sink_input(u, sinp);

            pa_policy_group_insert_sink_input(u, gnam, sinp);

            pa_log_debug("new sink_input %s (idx=%d) (group=%s)",
                         snam, idx, gnam);
        }
        break;
        
    case PA_SUBSCRIPTION_EVENT_CHANGE:
        break;
        
    case PA_SUBSCRIPTION_EVENT_REMOVE:
        pa_policy_group_remove_sink_input(u, idx);
        pa_log_debug("sink input removed (idx=%d)", idx);
        break;
        
    default:
        pa_log("%s: unknown sink input event type %d", __FILE__, et);
        break;
    }
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
