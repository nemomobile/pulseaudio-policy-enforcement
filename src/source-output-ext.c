#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <pulsecore/pulsecore-config.h>

#include <pulse/def.h>
#include <pulse/proplist.h>
#include <pulsecore/sink.h>
#include <pulsecore/sink-input.h>

#include "policy-group.h"
#include "source-output-ext.h"
#include "classify.h"



/* hooks */
static pa_hook_result_t source_output_put(void *, void *, void *);
static pa_hook_result_t source_output_unlink(void *, void *, void *);

static void handle_new_source_output(struct userdata *,
                                     struct pa_source_output *);
static void handle_removed_source_output(struct userdata *,
                                         struct pa_source_output *);


struct pa_sout_evsubscr *pa_source_output_ext_subscription(struct userdata *u)
{
    pa_core                 *core;
    pa_hook                 *hooks;
    struct pa_sout_evsubscr *subscr;
    pa_hook_slot            *put;
    pa_hook_slot            *unlink;
    
    pa_assert(u);
    pa_assert((core = u->core));

    hooks  = core->hooks;
    
    put    = pa_hook_connect(hooks + PA_CORE_HOOK_SOURCE_OUTPUT_PUT,
                             PA_HOOK_LATE, source_output_put, (void *)u);
    unlink = pa_hook_connect(hooks + PA_CORE_HOOK_SOURCE_OUTPUT_UNLINK,
                             PA_HOOK_LATE, source_output_unlink, (void *)u);

    subscr = pa_xnew0(struct pa_sout_evsubscr, 1);
    
    subscr->put    = put;
    subscr->unlink = unlink;

    
    return subscr;
}

void  pa_source_output_ext_subscription_free(struct pa_sout_evsubscr *subscr)
{
    if (subscr != NULL) {
        pa_hook_slot_free(subscr->put);
        pa_hook_slot_free(subscr->unlink);
        
        pa_xfree(subscr);
    }
}

void pa_source_output_ext_discover(struct userdata *u)
{
    void                    *state = NULL;
    pa_idxset               *idxset;
    struct pa_source_output *sout;

    pa_assert(u);
    pa_assert(u->core);
    pa_assert((idxset = u->core->source_outputs));

    while ((sout = pa_idxset_iterate(idxset, &state, NULL)) != NULL)
        handle_new_source_output(u, sout);
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


static pa_hook_result_t source_output_put(void *hook_data, void *call_data,
                                       void *slot_data)
{
    struct pa_source_output *sout = (struct pa_source_output *)call_data;
    struct userdata         *u    = (struct userdata *)slot_data;

    handle_new_source_output(u, sout);

    return PA_HOOK_OK;
}


static pa_hook_result_t source_output_unlink(void *hook_data, void *call_data,
                                          void *slot_data)
{
    struct pa_source_output *sout = (struct pa_source_output *)call_data;
    struct userdata         *u    = (struct userdata *)slot_data;

    handle_removed_source_output(u, sout);

    return PA_HOOK_OK;
}


static void handle_new_source_output(struct userdata         *u,
                                     struct pa_source_output *sout)
{
    char *snam;
    char *gnam;

    if (sout && u) {
        snam = pa_source_output_ext_get_name(sout);
        gnam = pa_classify_source_output(u, sout);

        pa_policy_group_insert_source_output(u, gnam, sout);

        pa_log_debug("new source_output %s (idx=%d) (group=%s)",
                     snam, sout->index, gnam);
    }
}


static void handle_removed_source_output(struct userdata         *u,
                                         struct pa_source_output *sout)
{
    char *snam;
    char *gnam;

    if (sout && u) {
        snam = pa_source_output_ext_get_name(sout);
        gnam = pa_classify_source_output(u, sout);

        pa_policy_group_remove_source_output(u, sout->index);

        pa_log_debug("removed source_output %s (idx=%d) (group=%s)",
                     snam, sout->index, gnam);
    }
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
