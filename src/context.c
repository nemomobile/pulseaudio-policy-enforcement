#include <stdarg.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "context.h"
#include "module-ext.h"
#include "card-ext.h"
#include "sink-ext.h"
#include "source-ext.h"
#include "sink-input-ext.h"
#include "source-output-ext.h"

static struct pa_policy_context_variable
            *add_variable(struct pa_policy_context *, const char *);
static void delete_variable(struct pa_policy_context *,
                            struct pa_policy_context_variable *);

static struct pa_policy_context_rule
            *add_rule(struct pa_policy_context_rule **,
                      enum pa_classify_method, const char *);
static void  delete_rule(struct pa_policy_context_rule **,
                         struct pa_policy_context_rule  *);

static void  append_action(union pa_policy_context_action **,
                           union pa_policy_context_action *);
static void  delete_action(union pa_policy_context_action **,
                           union pa_policy_context_action *);
static int perform_action(struct userdata *, union pa_policy_context_action *,
                          char *);

static int   match_setup(struct pa_policy_match *, enum pa_classify_method,
                         const char *, enum pa_classify_method *);
static void  match_cleanup(struct pa_policy_match *);

static int   value_setup(union pa_policy_value *, enum pa_policy_value_type,
                         va_list);
static void  value_cleanup(union pa_policy_value *);

static void register_object(struct pa_policy_object *,
                            enum pa_policy_object_type,
                            const char *, void *, int);
static void unregister_object(struct pa_policy_object *,
                              enum pa_policy_object_type, const char *,
                              void *, unsigned long, int);
static const char *get_object_property(struct pa_policy_object *,const char *);
static void set_object_property(struct pa_policy_object *,
                                const char *, const char *);
static void delete_object_property(struct pa_policy_object *, const char *);
static pa_proplist *get_object_proplist(struct pa_policy_object *);
static int object_assert(struct userdata *, struct pa_policy_object *);
static const char *object_name(struct pa_policy_object *);
static void fire_object_property_changed_hook(struct pa_policy_object *object);

static unsigned long object_index(enum pa_policy_object_type, void *);
static const char *object_type_str(enum pa_policy_object_type);

/* activities */
static struct pa_policy_activity_variable
            *get_activity_variable(struct userdata *u, struct pa_policy_context *, const char *, const int);
static void delete_activity(struct pa_policy_context *,
                            struct pa_policy_activity_variable *);

struct pa_policy_context *pa_policy_context_new(struct userdata *u)
{
    struct pa_policy_context *ctx;

    ctx = pa_xmalloc0(sizeof(*ctx));

    return ctx;
}

void pa_policy_context_free(struct pa_policy_context *ctx)
{
    if (ctx != NULL) {

        while (ctx->variables != NULL)
            delete_variable(ctx, ctx->variables);

        while (ctx->activities != NULL)
            delete_activity(ctx, ctx->activities);

        pa_xfree(ctx);
    }
}

static void register_rule(struct pa_policy_context_rule *rule,
                          enum pa_policy_object_type type,
                          const char *name, void *ptr) {
    union  pa_policy_context_action    *actn;
    struct pa_policy_set_property      *setprop;
    struct pa_policy_del_property      *delprop;
    struct pa_policy_object            *object;
    int                                 lineno;

    for (actn = rule->actions;  actn != NULL;  actn = actn->any.next) {

        switch (actn->any.type) {

        case pa_policy_set_property:
            setprop = &actn->setprop;
            lineno  = setprop->lineno;
            object  = &setprop->object;
            break;

        case pa_policy_delete_property:
            delprop = &actn->delprop;
            lineno  = delprop->lineno;
            object  = &delprop->object;
            break;

        default:
            continue;
        } /* switch */

        register_object(object, type, name, ptr, lineno);

    }  /* for actn */
}

void pa_policy_context_register(struct userdata *u,
                                enum pa_policy_object_type what,
                                const char *name, void *ptr)
{
    struct pa_policy_context_variable *var;
    struct pa_policy_context_rule     *rule;

    for (var = u->context->variables;   var != NULL;   var = var->next) {
        for (rule = var->rules;   rule != NULL;   rule = rule->next)
            register_rule(rule, what, name, ptr);
    }  /*  for var */
}

static void unregister_rule(struct pa_policy_context_rule *rule,
                            enum pa_policy_object_type type,
                            const char *name,
                            void *ptr,
                            unsigned long index)
{
    union  pa_policy_context_action    *actn;
    struct pa_policy_set_property      *setprop;
    struct pa_policy_del_property      *delprop;
    struct pa_policy_object            *object;
    int                                 lineno;

    for (actn = rule->actions;  actn != NULL;  actn = actn->any.next) {

        switch (actn->any.type) {

        case pa_policy_set_property:
            setprop = &actn->setprop;
            lineno  = setprop->lineno;
            object  = &setprop->object;
            break;

        case pa_policy_delete_property:
            delprop = &actn->delprop;
            lineno  = delprop->lineno;
            object  = &delprop->object;
            break;

        default:
            continue;
        } /* switch */

        unregister_object(object, type, name, ptr, index, lineno);

    } /* for actn */
}

void pa_policy_context_unregister(struct userdata *u,
                                  enum pa_policy_object_type type,
                                  const char *name,
                                  void *ptr,
                                  unsigned long index)
{
    struct pa_policy_context_variable *var;
    struct pa_policy_context_rule     *rule;

    for (var = u->context->variables;   var != NULL;   var = var->next) {
        for (rule = var->rules;   rule != NULL;   rule = rule->next)
            unregister_rule(rule, type, name, ptr, index);
    }  /* for var */
}

struct pa_policy_context_rule *
pa_policy_context_add_property_rule(struct userdata *u, const char *varname,
                                    enum pa_classify_method method, const char *arg)
{
    struct pa_policy_context_variable *variable;
    struct pa_policy_context_rule     *rule;

    variable = add_variable(u->context, varname);
    rule     = add_rule(&variable->rules, method, arg);

    return rule;
}

void
pa_policy_context_add_property_action(struct pa_policy_context_rule *rule,
                                      int                         lineno,
                                      enum pa_policy_object_type  obj_type,
                                      enum pa_classify_method     obj_classify,
                                      const char                 *obj_name,
                                      const char                 *prop_name,
                                      enum pa_policy_value_type   value_type,
                                      ...                     /* value_arg */)
{
    union pa_policy_context_action *action;
    struct pa_policy_set_property  *setprop;
    va_list                         value_arg;

    action  = pa_xmalloc0(sizeof(*action));
    setprop = &action->setprop; 
    
    setprop->type   = pa_policy_set_property;
    setprop->lineno = lineno;

    setprop->object.type = obj_type;
    match_setup(&setprop->object.match, obj_classify, obj_name, NULL);

    setprop->property = pa_xstrdup(prop_name);

    va_start(value_arg, value_type);
    value_setup(&setprop->value, value_type, value_arg);
    va_end(value_arg);

    append_action(&rule->actions, action);
}

void
pa_policy_context_delete_property_action(struct pa_policy_context_rule *rule,
                                         int                      lineno,
                                         enum pa_policy_object_type obj_type,
                                         enum pa_classify_method  obj_classify,
                                         const char              *obj_name,
                                         const char              *prop_name)
{
    union pa_policy_context_action *action;
    struct pa_policy_del_property  *delprop;

    action  = pa_xmalloc0(sizeof(*action));
    delprop = &action->delprop; 

    delprop->type   = pa_policy_delete_property;
    delprop->lineno = lineno;

    delprop->object.type = obj_type;
    match_setup(&delprop->object.match, obj_classify, obj_name, NULL);

    delprop->property = pa_xstrdup(prop_name);

    append_action(&rule->actions, action);
}

int pa_policy_context_variable_changed(struct userdata *u, const char *name,
                                       const char *value)
{
    struct pa_policy_context_variable *var;
    struct pa_policy_context_rule     *rule;
    union pa_policy_context_action    *actn;
    int                                success;

    success = true;

    for (var = u->context->variables;  var != NULL;  var = var->next) {
        if (!strcmp(name, var->name)) {
            if (!strcmp(value, var->value))
                pa_log_debug("no value change -> no action");
            else {
                pa_xfree(var->value);
                var->value = pa_xstrdup(value);

                for (rule = var->rules;  rule != NULL;  rule = rule->next) {
                    if (rule->match.method(value, &rule->match.arg)) {
                        for (actn = rule->actions; actn; actn = actn->any.next)
                        {
                            if (u->context->variable_change_count == PA_POLICY_CONTEXT_MAX_CHANGES) {
                                pa_log_warn("Max policy context value changes, dropping '%s':'%s'", name, value);
                                return false;
                            } else {
                                u->context->variable_change[u->context->variable_change_count].action = actn;
                                u->context->variable_change[u->context->variable_change_count].value = pa_xstrdup(value);
                                u->context->variable_change_count++;
                            }
                        } /* for actn */
                    } /* if rule */
                } /* for rule */
            }
            
            break;
        }
    } /* for var */

    return success;
}

void pa_policy_context_variable_commit(struct userdata *u)
{
    union pa_policy_context_action *action;
    char *value;

    pa_assert(u);
    pa_assert(u->context);

    while (u->context->variable_change_count) {
        u->context->variable_change_count--;

        action = u->context->variable_change[u->context->variable_change_count].action;
        value  = u->context->variable_change[u->context->variable_change_count].value;

        if (!perform_action(u, action, value))
            pa_log("Failed to perform action for value %s", value);
        pa_xfree(value);
    }
}

static
struct pa_policy_context_variable *add_variable(struct pa_policy_context *ctx,
                                                const char *name)
{
    struct pa_policy_context_variable *var;
    struct pa_policy_context_variable *last;

    for (last = (struct pa_policy_context_variable *)&ctx->variables;
         last->next != NULL;
         last = last->next)
    {
        var = last->next;

        if (!strcmp(name, var->name))
            return var;
    }

    var = pa_xmalloc0(sizeof(*var));

    var->name  = pa_xstrdup(name);
    var->value = pa_xstrdup("");

    last->next = var;

    pa_log_debug("created context variable '%s'", var->name);

    return var;
}

static void delete_activity(struct pa_policy_context           *ctx,
                            struct pa_policy_activity_variable *variable)
{
    struct pa_policy_activity_variable *last;

    for (last = (struct pa_policy_activity_variable *)&ctx->activities;
         last->next != NULL;
         last = last->next) {

        if (last->next == variable) {
            last->next = variable->next;

            pa_xfree(variable->device);

            while (variable->active_rules != NULL)
                delete_rule(&variable->active_rules, variable->active_rules);
            while (variable->inactive_rules != NULL)
                delete_rule(&variable->inactive_rules, variable->inactive_rules);

            pa_xfree(variable);
            return;
        }
    }

    pa_log("%s(): confused with data structures: can't find activity variable",
           __FUNCTION__);
}

static void delete_variable(struct pa_policy_context          *ctx,
                            struct pa_policy_context_variable *variable)
{
    struct pa_policy_context_variable *last;
    
    for (last = (struct pa_policy_context_variable *)&ctx->variables;
         last->next != NULL;
         last = last->next)
    {
        if (last->next == variable) {
            last->next = variable->next;

#if 0
            pa_log_debug("delete context variable '%s'", variable->name);
#endif

            pa_xfree(variable->name);

            while (variable->rules != NULL)
                delete_rule(&variable->rules, variable->rules);

            pa_xfree(variable);

            return;
        }
    }

    pa_log("%s(): confused with data structures: can't find variable",
           __FUNCTION__);
}

static struct pa_policy_context_rule *
add_rule(struct pa_policy_context_rule    **rules,
         enum pa_classify_method            method,
         const char                        *arg)
{
    struct pa_policy_context_rule *rule = pa_xmalloc0(sizeof(*rule));
    struct pa_policy_context_rule *last;
    enum pa_classify_method        method_status;

    if (!match_setup(&rule->match, method, arg, &method_status)) {
        pa_log("%s: invalid rule definition (method %s)",
               __FUNCTION__, pa_classify_method_str(method_status));
        pa_xfree(rule);
        return NULL;
    };

    for (last = (struct pa_policy_context_rule *)rules;
         last->next != NULL;
         last = last->next)
        ;

    last->next = rule;

    return rule;
}

static void delete_rule(struct pa_policy_context_rule **rules,
                        struct pa_policy_context_rule  *rule)
{
    struct pa_policy_context_rule *last;

    for (last = (struct pa_policy_context_rule *)rules;
         last->next != NULL;
         last = last->next)
    {
        if (last->next == rule) {
            last->next = rule->next;

            match_cleanup(&rule->match);

            while (rule->actions != NULL)
                delete_action(&rule->actions, rule->actions);

            pa_xfree(rule);

            return;
        }
    } 

    pa_log("%s(): confused with data structures: can't find rule",
           __FUNCTION__);
}


static void append_action(union pa_policy_context_action **actions,
                          union pa_policy_context_action  *action)
{
   union pa_policy_context_action *last;

    for (last = (union pa_policy_context_action *)actions;
         last->any.next != NULL;
         last = last->any.next)
        ;

    last->any.next = action;
}

static void delete_action(union pa_policy_context_action **actions,
                          union pa_policy_context_action  *action)
{
    union pa_policy_context_action *last;
    struct pa_policy_set_property  *setprop;

    for (last = (union pa_policy_context_action *)actions;
         last->any.next != NULL;
         last = last->any.next)
    {
        if (last->any.next == action) {
            last->any.next = action->any.next;

            switch (action->any.type) {

            case pa_policy_set_property:
                setprop = &action->setprop;

                match_cleanup(&setprop->object.match);
                pa_xfree(setprop->property);
                value_cleanup(&setprop->value);

                break;

            default:
                pa_log("%s(): confused with data structure: invalid action "
                       "type %d", __FUNCTION__, action->any.type);
                return;         /* better to leak than corrupt :) */
            }

            pa_xfree(action);

            return;
        }
    }

    pa_log("%s(): confused with data structures: can't find action",
           __FUNCTION__);
}

static int perform_action(struct userdata                *u,
                          union pa_policy_context_action *action,
                          char                           *var_value)
{
    struct pa_policy_set_property *setprop;
    struct pa_policy_del_property *delprop;
    struct pa_policy_object       *object;
    const char                    *old_value;
    const char                    *prop_value;
    const char                    *objname;
    const char                    *objtype;
    int                            success;

    switch (action->any.type) {

    case pa_policy_set_property:
        setprop = &action->setprop;
        object  = &setprop->object;

        if (!object_assert(u, object))
            success = false;
        else {
            switch (setprop->value.type) {

            case pa_policy_value_constant:
                prop_value = setprop->value.constant.string;
                break;

            case pa_policy_value_copy:
                prop_value = var_value;
                break;
                
            default:
                prop_value = NULL;
                break;
            }
            
            if (prop_value == NULL)
                success = false;
            else {
                success = true;

                old_value = get_object_property(object, setprop->property);
                objname   = object_name(object);
                objtype   = object_type_str(object->type);
                
                if (!strcmp(prop_value, old_value)) {
                    pa_log_debug("%s '%s' property '%s' value is already '%s'",
                                 objtype, objname, setprop->property,
                                 prop_value);
                }
                else {
                    pa_log_debug("setting %s '%s' property '%s' to '%s'",
                                 objtype, objname, setprop->property,
                                 prop_value);

                    set_object_property(object, setprop->property, prop_value);
                }

                /* Forward shared strings */
                pa_shared_data_sets(u->shared, setprop->property, prop_value);
            }
        }
        break;

    case pa_policy_delete_property:
        delprop = &action->delprop;
        object  = &delprop->object;

        if (!object_assert(u, object))
            success = false;
        else {
            success = true;

            objname = object_name(object);
            objtype = object_type_str(object->type);
            
            pa_log_debug("deleting %s '%s' property '%s'",
                         objtype, objname, delprop->property);
            
            delete_object_property(object, delprop->property);
        }
        break;

    default:
        success = false;
        break;
    }

    return success;
}

static int match_setup(struct pa_policy_match  *match,
                       enum pa_classify_method  method,
                       const char              *arg,
                       enum pa_classify_method *method_name_ret)
{
    enum pa_classify_method method_name = method;
    int   success = true;

    switch (method) {

    case pa_method_equals:
        match->method = pa_classify_method_equals;
        match->arg.string = pa_xstrdup(arg);
        break;

    case pa_method_startswith:
        match->method = pa_classify_method_startswith;
        match->arg.string = pa_xstrdup(arg);
        break;

    case pa_method_true:
        match->method = pa_classify_method_true;
        memset(&match->arg, 0, sizeof(match->arg));
        break;

    case pa_method_matches:
        if (regcomp(&match->arg.rexp, arg, 0) == 0) {
            match->method = pa_classify_method_matches;
            break;
        }
        /* intentional fall trough */

    default:
        memset(match, 0, sizeof(*match));
        method_name = pa_method_unknown;
        success = false;
        break;
    };

    if (method_name_ret != NULL)
        *method_name_ret = method_name;

    return success;
}


static void match_cleanup(struct pa_policy_match *match)
{
    if (match->method == pa_classify_method_matches)
        regfree(&match->arg.rexp);
    else
        pa_xfree((void *)match->arg.string);

    memset(match, 0, sizeof(*match));
}

static int value_setup(union pa_policy_value     *value,
                       enum pa_policy_value_type  type,
                       va_list                    ap)
{
    struct pa_policy_value_constant *constant;
    struct pa_policy_value_copy     *copy;
    va_list  arg;
    char    *string;
    int      success = true;

    va_copy(arg, ap);

    switch (type) {

    case pa_policy_value_constant:
        constant = &value->constant;
        string   = va_arg(arg, char *);

        constant->type   = pa_policy_value_constant;
        constant->string = pa_xstrdup(string);

        break;

    case pa_policy_value_copy:
        copy = &value->copy;

        copy->type = pa_policy_value_copy;

        break;

    default:
        memset(value, 0, sizeof(*value));
        success = false;
        break;
    }

    va_end(arg);

    return success;
}

static void value_cleanup(union pa_policy_value *value)
{
    switch (value->type) {

    case pa_policy_value_constant:
        pa_xfree(value->constant.string);
        break;

    default:
        break;
    }
}

static void register_object(struct pa_policy_object *object,
                            enum pa_policy_object_type type,
                            const char *name, void *ptr, int lineno)
{
    const char    *type_str;

    if (object->type == type && object->match.method(name,&object->match.arg)){

        type_str = object_type_str(type);

        if (object->ptr != NULL) {
            pa_log("multiple match for %s '%s' (line %d in config file)",
                   type_str, name, lineno);
        }
        else {
            pa_log_debug("registering context-rule for %s '%s' "
                         "(line %d in config file)", type_str, name, lineno);

            object->ptr   = ptr;
            object->index = object_index(type, ptr);

        }
    }
}

static void unregister_object(struct pa_policy_object *object,
                              enum pa_policy_object_type type,
                              const char *name,
                              void *ptr,
                              unsigned long index,
                              int lineno)
{
    if (( ptr &&                ptr == object->ptr             ) ||
        (!ptr && type == object->type && index == object->index)   ) {

        pa_log_debug("unregistering context-rule for %s '%s' "
                     "(line %d in config file)",
                     object_type_str(object->type), name, lineno);

        object->ptr   = NULL;
        object->index = PA_IDXSET_INVALID;
    }
}


static const char *get_object_property(struct pa_policy_object *object,
                                       const char *property)
{
    pa_proplist *proplist;
    const char  *propval;
    const char  *value = "<undefined>";

    if (object->ptr != NULL) {


        if ((proplist = get_object_proplist(object)) != NULL) {
            propval = pa_proplist_gets(proplist, property);

            if (propval != NULL && propval[0] != '\0')
                value = propval;
        }
    }

    return value;
}

static void set_object_property(struct pa_policy_object *object,
                                const char *property, const char *value)
{
    pa_proplist *proplist;

    if (object->ptr != NULL) {
        if ((proplist = get_object_proplist(object)) != NULL) {
            pa_proplist_sets(proplist, property, value);
            fire_object_property_changed_hook(object);
        }
    }
}

static void delete_object_property(struct pa_policy_object *object,
                                   const char *property)
{
    pa_proplist *proplist;

    if (object->ptr != NULL) {
        if ((proplist = get_object_proplist(object)) != NULL) {
            pa_proplist_unset(proplist, property);
            fire_object_property_changed_hook(object);
        }
    }
}

static pa_proplist *get_object_proplist(struct pa_policy_object *object)
{
    pa_proplist *proplist;

    switch (object->type) {

    case pa_policy_object_module:
        proplist = ((struct pa_module *)object->ptr)->proplist;
        break;

    case pa_policy_object_card:
        proplist = ((struct pa_card *)object->ptr)->proplist;
        break;

    case pa_policy_object_sink:
        proplist = ((struct pa_sink *)object->ptr)->proplist;
        break;
        
    case pa_policy_object_source:
        proplist = ((struct pa_source *)object->ptr)->proplist;
        break;
        
    case pa_policy_object_sink_input:
        proplist = ((struct pa_sink_input *)object->ptr)->proplist;
        break;
        
    case pa_policy_object_source_output:
        proplist = ((struct pa_source_output *)object->ptr)->proplist;
        break;
        
    default:
        proplist = NULL;
        break;
    }

    return proplist;
}


static int object_assert(struct userdata *u, struct pa_policy_object *object)
{
    void *ptr;

    pa_assert(u);
    pa_assert(u->core);

    if (object->ptr != NULL && object->index != PA_IDXSET_INVALID) {

        switch (object->type) {

        case pa_policy_object_module:
            ptr = pa_idxset_get_by_index(u->core->modules, object->index);

            if (ptr != object->ptr)
                break;

            return true;

        case pa_policy_object_card:
        case pa_policy_object_sink:
        case pa_policy_object_source:
        case pa_policy_object_sink_input:
        case pa_policy_object_source_output:
            return true;

        default:
            break;
        }
    }
    
    pa_log("%s() failed", __FUNCTION__);

    return false;
}

static const char *object_name(struct pa_policy_object *object)
{
    const char *name;

    switch (object->type) {

    case pa_policy_object_module:
        name = pa_module_ext_get_name((struct pa_module *)object->ptr);
        break;

    case pa_policy_object_card:
        name = pa_card_ext_get_name((struct pa_card *)object->ptr);
        break;

    case pa_policy_object_sink:
        name = pa_sink_ext_get_name((struct pa_sink *)object->ptr);
        break;
        
    case pa_policy_object_source:
        name = pa_source_ext_get_name((struct pa_source *)object->ptr);
        break;
        
    case pa_policy_object_sink_input:
        name = pa_sink_input_ext_get_name((struct pa_sink_input *)object->ptr);
        break;
        
    case pa_policy_object_source_output:
        name = pa_source_output_ext_get_name(
                     (struct pa_source_output *)object->ptr);
        break;
        
    default:
        name = "<unknown>";
        break;
    }

    return name;
}

static void fire_object_property_changed_hook(struct pa_policy_object *object)
{
    pa_core                 *core;
    pa_core_hook_t           hook;
    struct pa_sink          *sink;
    struct pa_source        *src;
    struct pa_sink_input    *sinp;
    struct pa_source_output *sout;

   switch (object->type) {

    case pa_policy_object_sink:
        sink = object->ptr;
        core = sink->core;
        hook = PA_CORE_HOOK_SINK_PROPLIST_CHANGED;
        break;
        
    case pa_policy_object_source:
        src  = object->ptr;
        core = src->core;
        hook = PA_CORE_HOOK_SOURCE_PROPLIST_CHANGED;
        break;
        
    case pa_policy_object_sink_input:
        sinp = object->ptr;
        core = sinp->core;
        hook = PA_CORE_HOOK_SINK_INPUT_PROPLIST_CHANGED;
        break;
        
    case pa_policy_object_source_output:
        sout = object->ptr;
        core = sout->core;
        hook = PA_CORE_HOOK_SOURCE_OUTPUT_PROPLIST_CHANGED;
        break;
        
    default:
        return;
    }

   pa_hook_fire(&core->hooks[hook], object->ptr);
}

static unsigned long object_index(enum pa_policy_object_type type, void *ptr)
{
    switch (type) {
    case pa_policy_object_module:
        return ((struct pa_module *)ptr)->index;
    case pa_policy_object_card:
        return ((struct pa_card *)ptr)->index;
    case pa_policy_object_sink:
        return ((struct pa_sink *)ptr)->index;
    case pa_policy_object_source:
        return ((struct pa_source *)ptr)->index;
    case pa_policy_object_sink_input:
        return ((struct pa_sink_input *)ptr)->index;
    case pa_policy_object_source_output:
        return ((struct pa_source_output *)ptr)->index;
    default:
        return PA_IDXSET_INVALID;
    }
}


static const char *object_type_str(enum pa_policy_object_type type)
{
    switch (type) {
    case pa_policy_object_module:         return "module";
    case pa_policy_object_card:           return "card";
    case pa_policy_object_sink:           return "sink";
    case pa_policy_object_source:         return "source";
    case pa_policy_object_sink_input:     return "sink-input";
    case pa_policy_object_source_output:  return "source-output";
    default:                              return "<unknown>";
    }
}

static
struct pa_policy_activity_variable *get_activity_variable(struct userdata *u, struct pa_policy_context *ctx,
                                                          const char *device, const int default_state)
{
    struct pa_policy_activity_variable *var;
    struct pa_policy_activity_variable *last;

    for (last = (struct pa_policy_activity_variable *)&ctx->activities;
         last->next != NULL;
         last = last->next)
    {
        var = last->next;

        if (!strcmp(device, var->device))
            return var;
    }

    var = pa_xmalloc0(sizeof(*var));

    var->device = pa_xstrdup(device);
    var->default_state = default_state;
    var->userdata = u;

    last->next = var;

    pa_log_debug("created context activity variable '%s', default %d", var->device, var->default_state);

    return var;
}

void
pa_policy_activity_add(struct userdata *u, const char *device, const int default_state)
{
    /* create new activity variable here */
    get_activity_variable(u, u->context, device, default_state);
}

struct pa_policy_context_rule *
pa_policy_activity_add_active_rule(struct userdata *u, const char *device,
                                   enum pa_classify_method method, const char *sink_name)
{
    struct pa_policy_activity_variable *variable;
    struct pa_policy_context_rule      *rule;

    pa_assert_se((variable = get_activity_variable(u, u->context, device, -1)));
    rule = add_rule(&variable->active_rules, method, sink_name);

    return rule;
}

struct pa_policy_context_rule *
pa_policy_activity_add_inactive_rule(struct userdata *u, const char *device,
                                     enum pa_classify_method method, const char *sink_name)
{
    struct pa_policy_activity_variable *variable;
    struct pa_policy_context_rule      *rule;

    pa_assert_se((variable = get_activity_variable(u, u->context, device, -1)));
    rule = add_rule(&variable->inactive_rules, method, sink_name);

    return rule;
}

/* force_state can be -1  - do not force , 0 force inactive, 1 force active */
static int perform_activity_action(pa_sink *sink, struct pa_policy_activity_variable *var, int force_state) {
    struct pa_policy_context_rule     *rule;
    union pa_policy_context_action    *actn;
    int                                is_opened;

    pa_assert(sink);

    if ((force_state != -1 && force_state == 1) ||
        (force_state == -1 && PA_SINK_IS_OPENED(pa_sink_get_state(sink)))) {
        rule = var->active_rules;
        is_opened = 1;
    } else {
        rule = var->inactive_rules;
        is_opened = 0;
    }

    for ( ;  rule != NULL;  rule = rule->next) {
        if (rule->match.method(sink->name, &rule->match.arg)) {

            if (force_state == -1 && var->sink_opened != -1 && var->sink_opened == is_opened) {
                pa_log_debug("Already executed actions for state change, skip.");
                return 1;
            }

            var->sink_opened = is_opened;

            for (actn = rule->actions; actn; actn = actn->any.next)
            {
                if (!perform_action(var->userdata, actn, NULL))
                    pa_log("Failed to perform activity action.");
            }
        }
    }

    return 1;
}

static pa_hook_result_t sink_state_changed_cb(pa_core *c, pa_object *o, struct pa_policy_activity_variable *var) {
    pa_sink *sink;

    pa_assert(c);
    pa_object_assert_ref(o);
    pa_assert(var);

    if (pa_sink_isinstance(o)) {
        sink = PA_SINK(o);
        perform_activity_action(sink, var, -1);
    }

    return PA_HOOK_OK;
}

static void enable_activity(struct userdata *u, struct pa_policy_activity_variable *var) {
    pa_sink                            *sink;
    uint32_t                            idx = 0;

    pa_assert(u);
    pa_assert(var);

    if (var->sink_state_changed_hook_slot)
        return;

    var->sink_state_changed_hook_slot = pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_SINK_STATE_CHANGED],
                                                        PA_HOOK_EARLY,
                                                        (pa_hook_cb_t) sink_state_changed_cb, var);

    var->sink_opened = -1;
    pa_log_debug("enabling activity for %s", var->device);
    PA_IDXSET_FOREACH(sink, u->core->sinks, idx)
        perform_activity_action(sink, var, -1);
}

static void disable_activity(struct userdata *u, struct pa_policy_activity_variable *var) {
    pa_sink                            *sink;
    uint32_t                            idx = 0;

    pa_assert(u);
    pa_assert(var);

    if (!var->sink_state_changed_hook_slot)
        return;

    var->sink_opened = -1;
    pa_log_debug("disabling activity for %s: defaulting to %d", var->device, var->default_state);
    PA_IDXSET_FOREACH(sink, u->core->sinks, idx)
        perform_activity_action(sink, var, var->default_state);

    pa_hook_slot_free(var->sink_state_changed_hook_slot);
    var->sink_state_changed_hook_slot = NULL;
}

int pa_policy_activity_device_changed(struct userdata *u, const char *device)
{
    struct pa_policy_activity_variable *var;
    int                                 success = 0;

    for (var = u->context->activities;  var != NULL;  var = var->next) {
        if (!strcmp(device, var->device))
            enable_activity(u, var);
        else
            disable_activity(u, var);
    }

    return success;
}

void pa_policy_activity_register(struct userdata *u,
                                 enum pa_policy_object_type type,
                                 const char *name, void *ptr)
{
    struct pa_policy_activity_variable *var;
    struct pa_policy_context_rule      *rule;

    for (var = u->context->activities;   var != NULL;   var = var->next) {
        for (rule = var->active_rules;   rule != NULL;   rule = rule->next)
            register_rule(rule, type, name, ptr);
        for (rule = var->inactive_rules;   rule != NULL;   rule = rule->next)
            register_rule(rule, type, name, ptr);
    }  /*  for var */
}

void pa_policy_activity_unregister(struct userdata *u,
                                   enum pa_policy_object_type type,
                                   const char *name,
                                   void *ptr,
                                   unsigned long index)
{
    struct pa_policy_activity_variable *var;
    struct pa_policy_context_rule      *rule;

    for (var = u->context->activities;   var != NULL;   var = var->next) {
        for (rule = var->active_rules;   rule != NULL;   rule = rule->next)
            unregister_rule(rule, type, name, ptr, index);
        for (rule = var->inactive_rules;   rule != NULL;   rule = rule->next)
            unregister_rule(rule, type, name, ptr, index);
    }  /* for var */
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
