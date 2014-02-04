#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/def.h>
#include <pulse/proplist.h>
#include <pulse/volume.h>
#include <pulsecore/sink.h>
#include <pulsecore/sink-input.h>

#include "userdata.h"
#include "index-hash.h"
#include "policy-group.h"
#include "sink-input-ext.h"
#include "sink-ext.h"
#include "classify.h"
#include "context.h"

/* hooks */
static pa_hook_result_t sink_input_neew(void *, void *, void *);
static pa_hook_result_t sink_input_put(void *, void *, void *);
static pa_hook_result_t sink_input_unlink(void *, void *, void *);

static struct pa_policy_group* get_group(struct userdata *, struct pa_sink_input *, uint32_t *);
static struct pa_policy_group* get_group_or_classify(struct userdata *, struct pa_sink_input *, uint32_t *);
static void handle_new_sink_input(struct userdata *, struct pa_sink_input *);
static void handle_removed_sink_input(struct userdata *,
                                      struct pa_sink_input *);

struct pa_sinp_evsubscr *pa_sink_input_ext_subscription(struct userdata *u)
{
    pa_core                 *core;
    pa_hook                 *hooks;
    struct pa_sinp_evsubscr *subscr;
    pa_hook_slot            *neew;
    pa_hook_slot            *put;
    pa_hook_slot            *unlink;
    
    pa_assert(u);
    pa_assert_se((core = u->core));

    hooks  = core->hooks;
    
    /* PA_HOOK_EARLY - 2, i.e. before module-match */
    neew   = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_INPUT_NEW,
                             PA_HOOK_EARLY - 2, sink_input_neew, (void *)u);
    put    = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_INPUT_PUT,
                             PA_HOOK_LATE, sink_input_put, (void *)u);
    unlink = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_INPUT_UNLINK,
                             PA_HOOK_LATE, sink_input_unlink, (void *)u);


    subscr = pa_xnew0(struct pa_sinp_evsubscr, 1);
    
    subscr->neew   = neew;
    subscr->put    = put;
    subscr->unlink = unlink;

    return subscr;
}

void  pa_sink_input_ext_subscription_free(struct pa_sinp_evsubscr *subscr)
{
    if (subscr != NULL) {
        pa_hook_slot_free(subscr->neew);
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

struct pa_sink_input_ext *pa_sink_input_ext_lookup(struct userdata      *u,
                                                   struct pa_sink_input *sinp)
{
    struct pa_sink_input_ext *ext;

    pa_assert(u);
    pa_assert(sinp);

    ext = pa_index_hash_lookup(u->hsi, sinp->index);

    return ext;
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

    pa_assert(sinp);

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
    pa_sink     *sink;
    int          retval;
    uint64_t     limit64;
    pa_volume_t  value;
    pa_cvolume  *factor;
    pa_cvolume  *real;
    int          changed;
    int          i;

    pa_assert(sinp);
    pa_assert_se((sink = sinp->sink));

    retval = 0;

    if (limit == 0)
        pa_sink_input_set_mute(sinp, TRUE, TRUE);
    else {
        pa_sink_input_set_mute(sinp, FALSE, TRUE);

        if (limit > PA_VOLUME_NORM)
            limit = PA_VOLUME_NORM;

        factor  = &sinp->volume_factor;
        real    = &sinp->real_ratio;
        limit64 = (uint64_t)limit * (uint64_t)PA_VOLUME_NORM;
        changed = FALSE;

        if (real->channels != factor->channels) {
            pa_log_debug("channel number mismatch");
            retval = -1;
        }
        else {
            for (i = 0;   i < factor->channels;   i++) {
                if (limit < real->values[i])
                    value = limit64 / (uint64_t)real->values[i];
                else
                    value = PA_VOLUME_NORM;

                if (value != factor->values[i]) {
                    changed = 1;
                    factor->values[i] = value;
                }
            }

            if (changed) {
                if (pa_sink_flat_volume_enabled(sink))
                    retval = 1;
                else {
                    pa_sw_cvolume_multiply(&sinp->soft_volume, real, factor);
                    pa_asyncmsgq_send(sink->asyncmsgq, PA_MSGOBJECT(sinp),
                                      PA_SINK_INPUT_MESSAGE_SET_SOFT_VOLUME,
                                      NULL, 0, NULL);
                }
            }
        }
    }

    return retval;
}


 
static pa_hook_result_t sink_input_neew(void *hook_data, void *call_data,
                                       void *slot_data)
{
    static uint32_t         route_flags = PA_POLICY_GROUP_FLAG_SET_SINK |
                                          PA_POLICY_GROUP_FLAG_ROUTE_AUDIO;
    static pa_volume_t      max_volume  = PA_VOLUME_NORM;


    struct pa_sink_input_new_data
                           *data = (struct pa_sink_input_new_data *)call_data;
    struct userdata        *u    = (struct userdata *)slot_data;
    uint32_t                flags;
    char                   *group_name;
    const char             *sinp_name;
    char                   *sink_name;
    int                     local_route;
    int                     local_volume;
    struct pa_policy_group *group;

    pa_assert(u);
    pa_assert(data);

    if ((group_name = pa_classify_sink_input_by_data(u,data,&flags)) != NULL &&
        (group      = pa_policy_group_find(u, group_name)          ) != NULL ){

        /* Let's just set the policy group property here already so that we
         * don't have to classify again when the sink input is put, because we
         * can just retrieve the group from the proplist. Also, this prevents
         * the classification from breaking later because of the proplist
         * overwriting done below. */
        pa_proplist_sets(data->proplist, PA_PROP_POLICY_GROUP, group_name);

        /* Proplist overwriting can also mess up the retrieval of
         * stream-specific flags later on, so we need to store those to the
         * proplist as well (ugly hack). We could probably cope without this
         * one though, since the stream-specific flags don't really seem to be
         * used. */
        pa_proplist_set(data->proplist, PA_PROP_POLICY_STREAM_FLAGS,
                        (void*)&flags, sizeof(flags));

        if (group->properties != NULL) {
            pa_proplist_update(data->proplist, PA_UPDATE_REPLACE, group->properties);
            pa_log_debug("new sink input inserted into %s. "
                         "force the following properties:", group_name);
        }

        if (group->sink != NULL) {
            sinp_name = pa_proplist_gets(data->proplist, PA_PROP_MEDIA_NAME);

            if (!sinp_name)
                sinp_name = "<unknown>";

            local_route  = flags & PA_POLICY_LOCAL_ROUTE;
            local_volume = flags & PA_POLICY_LOCAL_VOLMAX;

            if (group->mutebyrt && !local_route) {
                sink_name = u->nullsink->name;

                pa_log_debug("force stream '%s'/'%s' to sink '%s' due to "
                             "mute-by-route", group_name,sinp_name, sink_name);

#ifdef HAVE_OLD_LIBPULSE
                data->sink = u->nullsink->sink;
#else
                pa_sink_input_new_data_set_sink(data, u->nullsink->sink, false);
#endif
            }
            else if (group->flags & route_flags) {
                sink_name = pa_sink_ext_get_name(group->sink);

                pa_log_debug("force stream '%s'/'%s' to sink '%s'",
                             group_name, sinp_name, sink_name); 

#ifdef HAVE_OLD_LIBPULSE
                data->sink = group->sink;
#else
                pa_sink_input_new_data_set_sink(data, group->sink, false);
#endif
            }

            if (local_volume) {
                pa_log_debug("force stream '%s'/'%s' volume to %d",
                             group_name, sinp_name,
                             (max_volume * 100) / PA_VOLUME_NORM);
                
                pa_cvolume_set(&data->volume, data->channel_map.channels,
                               max_volume);

                data->volume_is_set      = TRUE;
                data->save_volume        = FALSE;
            }
        }

    }


    return PA_HOOK_OK;
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

static struct pa_policy_group* get_group(struct userdata *u, struct pa_sink_input *sinp, uint32_t *flags_ret)
{
    struct pa_policy_group *group = NULL;
    const char* group_name;
    const void *flags;
    size_t len_flags = 0;

    pa_assert(flags_ret);

    /* Just grab the group name from the proplist to avoid classifying multiple
     * times (and to avoid classifying incorrectly if properties are
     * overwritten when handling PA_CORE_HOOK_SINK_INPUT_NEW).*/
    group_name = pa_proplist_gets(sinp->proplist, PA_PROP_POLICY_GROUP);
    if (group_name && (group = pa_policy_group_find(u, group_name)) != NULL) {
        if (pa_proplist_get(sinp->proplist, PA_PROP_POLICY_STREAM_FLAGS, &flags, &len_flags) < 0 ||
            len_flags != sizeof(uint32_t)) {

            pa_log_warn("No stream flags in proplist or malformed flags.");
            *flags_ret = 0;
        } else
            *flags_ret = *(uint32_t *)flags;
    }

    return group;
}

static struct pa_policy_group* get_group_or_classify(struct userdata *u, struct pa_sink_input *sinp, uint32_t *flags_ret) {
    struct pa_policy_group *group;

    group = get_group(u, sinp, flags_ret);

    if (!group) {
        pa_log_warn("Sink input %s is missing a policy group. "
                    "Classifying...", pa_sink_input_ext_get_name(sinp));

        if (pa_classify_sink_input(u, sinp, flags_ret))
            group = get_group(u, sinp, flags_ret);
    }

    return group;
}

static void handle_new_sink_input(struct userdata      *u,
                                  struct pa_sink_input *sinp)
{
    struct      pa_policy_group *group = NULL;
    struct      pa_sink_input_ext *ext;
    uint32_t    idx;
    char       *sinp_name;
    int         group_volume;
    pa_cvolume  group_limit;
    uint32_t    flags;

    if (sinp && u) {
        idx  = sinp->index;
        sinp_name = pa_sink_input_ext_get_name(sinp);
        pa_assert_se((group = get_group_or_classify(u, sinp, &flags)));
        group_volume = group->flags & PA_POLICY_GROUP_FLAG_LIMIT_VOLUME;

        ext = pa_xmalloc0(sizeof(struct pa_sink_input_ext));
        ext->local.route = (flags & PA_POLICY_LOCAL_ROUTE) ? TRUE : FALSE;
        ext->local.mute  = (flags & PA_POLICY_LOCAL_MUTE ) ? TRUE : FALSE;
        pa_index_hash_add(u->hsi, idx, ext);

        /* Set volume factor in sink_input_put() so that we have our target sink and
         * channel_map defined properly. */
        if (group_volume && !group->mutebyrt &&
                 group->limit > 0 && group->limit < PA_VOLUME_NORM)
        {
            pa_log_debug("set stream '%s'/'%s' volume factor to %d",
                         group->name, sinp_name,
                         (group->limit * 100) / PA_VOLUME_NORM);

            pa_cvolume_set(&group_limit,
                           sinp->channel_map.channels,
                           group->limit);

            pa_sink_input_add_volume_factor(sinp, sinp_name, &group_limit);
        }

        pa_policy_context_register(u, pa_policy_object_sink_input, sinp_name, sinp);
        pa_policy_group_insert_sink_input(u, group->name, sinp, flags);

        pa_log_debug("new sink_input %s (idx=%u) (group=%s)", sinp_name, idx, group->name);
    }
}

static void handle_removed_sink_input(struct userdata      *u,
                                      struct pa_sink_input *sinp)
{
    struct pa_policy_group *group = NULL;
    struct pa_sink_input_ext *ext;
    struct pa_sink *sink;
    uint32_t        idx;
    char           *snam;
    uint32_t        flags;

    if (sinp && u) {
        idx  = sinp->index;
        sink = sinp->sink;
        snam = pa_sink_input_ext_get_name(sinp);
        pa_assert_se((group = get_group_or_classify(u, sinp, &flags)));

        if (flags & PA_POLICY_LOCAL_ROUTE)
            pa_sink_ext_restore_port(u, sink);

        if (flags & PA_POLICY_LOCAL_MUTE)
            pa_policy_groupset_restore_volume(u, sink);
            
        pa_policy_context_unregister(u, pa_policy_object_sink_input,
                                     snam, sinp, sinp->index);
        pa_policy_group_remove_sink_input(u, sinp->index);

        if ((ext = pa_index_hash_remove(u->hsi, idx)) == NULL)
            pa_log("no extension found for sink-input '%s' (idx=%u)",snam,idx);
        else {
            pa_xfree(ext);
        }

        pa_log_debug("removed sink_input '%s' (idx=%d) (group=%s)",
                     snam, idx, group->name);
    }
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
