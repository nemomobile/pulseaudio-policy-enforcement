#include <pulsecore/pulsecore-config.h>

#include <pulse/def.h>
#include <pulsecore/module.h>

#include "module-ext.h"
#include "context.h"

static void handle_module_events(pa_core *, pa_subscription_event_type_t,
                                 uint32_t, void *);
static void handle_new_module(struct userdata *, struct pa_module *);
static void handle_removed_module(struct userdata *, unsigned long);

struct pa_module_evsubscr *pa_module_ext_subscription(struct userdata *u)
{
    struct pa_module_evsubscr *subscr;

    pa_assert(u);
    pa_assert(u->core);

    subscr = pa_xnew0(struct pa_module_evsubscr, 1);

    subscr->ev = pa_subscription_new(u->core, 1<<PA_SUBSCRIPTION_EVENT_MODULE,
                                     handle_module_events, (void *)u);

    return subscr;
}

void pa_module_ext_subscription_free(struct pa_module_evsubscr *subscr)
{
    pa_assert(subscr);

    pa_subscription_free(subscr->ev);
}


void pa_module_ext_discover(struct userdata *u)
{
    void             *state = NULL;
    pa_idxset        *idxset;
    struct pa_module *module;

    pa_assert(u);
    pa_assert(u->core);
    pa_assert_se((idxset = u->core->modules));

    while ((module = pa_idxset_iterate(idxset, &state, NULL)) != NULL)
        handle_new_module(u, module);
}

char *pa_module_ext_get_name(struct pa_module *module)
{
    return module->name ? module->name : (char *)"<unknown>";
}

static void handle_module_events(pa_core *c, pa_subscription_event_type_t t,
                                 uint32_t idx, void *userdata)
{
    struct userdata    *u  = userdata;
    uint32_t            et = t & PA_SUBSCRIPTION_EVENT_TYPE_MASK;
    struct pa_module   *module;
    char               *name;

    pa_assert(u);
    
    switch (et) {

    case PA_SUBSCRIPTION_EVENT_NEW:
        if ((module = pa_idxset_get_by_index(c->modules, idx)) != NULL) {
            name = pa_module_ext_get_name(module);

            handle_new_module(u, module);
        }
        break;
        
    case PA_SUBSCRIPTION_EVENT_REMOVE:
        break;

    default:
        break;
    }
}

static void handle_new_module(struct userdata *u, struct pa_module *module)
{
    char     *name;
    uint32_t  idx;
    int       ret;

    if (module && u) {
        name = pa_module_ext_get_name(module);
        idx  = module->index;

        pa_policy_context_register(u, pa_policy_object_module, name, module);
    }
}

static void handle_removed_module(struct userdata *u, unsigned long idx)
{
    char name[256];

    if (u) {

        snprintf(name, sizeof(name), "module #%d", idx);

        pa_policy_context_unregister(u, pa_policy_object_module,
                                     name, NULL, idx);
    }
}



/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
