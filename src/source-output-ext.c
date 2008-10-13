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
#include "source-output-ext.h"
#include "classify.h"



static void handle_source_output_events(pa_core *,
                                        pa_subscription_event_type_t,
                                        uint32_t, void *);



pa_subscription *pa_source_output_ext_subscription(struct userdata *u)
{
    pa_subscription *subscr;
    
    pa_assert(u->core);
    
    subscr = pa_subscription_new(u->core,
                                 1<<PA_SUBSCRIPTION_EVENT_SOURCE_OUTPUT,
                                 handle_source_output_events, (void *)u);
    
    return subscr;
}

int pa_source_output_ext_set_policy_group(struct pa_source_output *sout, 
                                          char *group)
{
    int ret;

    pa_assert(sout);

    if (group) 
        ret = pa_proplist_sets(sout->proplist, PA_PROP_POLICY_GROUP, group);
    else
        ret = pa_proplist_unset(sout->proplist, PA_PROP_POLICY_GROUP);

    return ret;
}

char *pa_source_output_ext_get_policy_group(struct pa_source_output *sout)
{
    const char *group;

    pa_assert(sout);

    group = pa_proplist_gets(sout->proplist, PA_PROP_POLICY_GROUP);

    if (group == NULL)
        group = PA_POLICY_DEFAULT_GROUP_NAME;

    return (char *)group;
}

char *pa_source_output_ext_get_name(struct pa_source_output *sout)
{
    const char *name;

    pa_assert(sout);

    name = pa_proplist_gets(sout->proplist, PA_PROP_MEDIA_NAME);

    if (name == NULL)
        name = "<unknown>";
    
    return (char *)name;
}


static void handle_source_output_events(pa_core *c,
                                        pa_subscription_event_type_t t,
                                        uint32_t idx, void *userdata)
{
    struct userdata         *u  = userdata;
    uint32_t                 et = t & PA_SUBSCRIPTION_EVENT_TYPE_MASK;
    struct pa_source_output *sout;
    char                    *snam;
    char                    *gnam;
    
    pa_assert(u);
    
    switch (et) {

    case PA_SUBSCRIPTION_EVENT_NEW:
        if ((sout = pa_idxset_get_by_index(c->source_outputs, idx)) != NULL) {
            snam = pa_source_output_ext_get_name(sout);
            gnam = pa_classify_source_output(u, sout);

            pa_policy_group_insert_source_output(u, gnam, sout);

            pa_log_debug("new source output %s (idx=%d) (group=%s)",
                         snam, idx, gnam);
        }
        break;
        
    case PA_SUBSCRIPTION_EVENT_CHANGE:
        break;
        
    case PA_SUBSCRIPTION_EVENT_REMOVE:
        pa_policy_group_remove_source_output(u, idx);

        pa_log_debug("source output removed (idx=%d)", idx);
        break;
        
    default:
        pa_log("%s: unknown source output event type %d", __FILE__, et);
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
