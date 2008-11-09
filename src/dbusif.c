#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pulsecore/pulsecore-config.h>

#include "userdata.h"
#include "dbus-util.h"
#include "dbusif.h"
#include "classify.h"
#include "policy-group.h"
#include "source-ext.h"

#define ADMIN_DBUS_MANAGER          "org.freedesktop.DBus"
#define ADMIN_DBUS_PATH             "/org/freedesktop/DBus"
#define ADMIN_DBUS_INTERFACE        "org.freedesktop.DBus"

#define ADMIN_NAME_OWNER_CHANGED    "NameOwnerChanged"

#define POLICY_DBUS_INTERFACE       "com.nokia.policy"
#define POLICY_DBUS_MYPATH          "/com/nokia/policy/enforce/pulseaudio"
#define POLICY_DBUS_MYNAME          "com.nokia.policy.pulseaudio"
#define POLICY_DBUS_PDPATH          "/com/nokia/policy"
#define POLICY_DBUS_PDNAME          "org.freedesktop.ohm"

#define POLICY_DECISION             "decision"
#define POLICY_INFO                 "info"
#define POLICY_ACTIONS              "actions"
#define POLICY_STATUS               "status"


#define STRUCT_OFFSET(s,m) ((char *)&(((s *)0)->m) - (char *)0)

struct pa_policy_dbusif {
    pa_dbus_connection *conn;
    char               *ifnam;   /* signal interface */
    char               *mypath;  /* my signal path */
    char               *pdpath;  /* policy daemon's signal path */
    char               *pdnam;   /* policy daemon's D-Bus name */
    char               *admrule; /* match rule to catch name changes */
    char               *polrule; /* match rule to catch policy signals */
    int                 regist;  /* wheter or not registered to policy daemon*/
};

struct actdsc {                 /* action descriptor */
    const char         *name;
    int               (*parser)(struct userdata *u, DBusMessageIter *iter);
};

struct argdsc {                 /* argument descriptor for actions */
    const char         *name;
    int                 offs;
    int                 type;
};

struct argrt {                  /* audio_route arguments */
    char               *type;
    char               *device;
};

struct argvol {                 /* volume_limit arguments */
    char               *group;
    char               *limit;
};

struct argcork {                /* audio_cork arguments */
    char               *group;
    char               *cork;
};

struct argmute {
    char               *device;
    char               *mute;
};

static int action_parser(DBusMessageIter *, struct argdsc *, void *, int);
static int audio_route_parser(struct userdata *, DBusMessageIter *);
static int volume_limit_parser(struct userdata *, DBusMessageIter *);
static int audio_cork_parser(struct userdata *, DBusMessageIter *);
static int audio_mute_parser(struct userdata *, DBusMessageIter *);

static DBusHandlerResult filter(DBusConnection *, DBusMessage *, void *);
static void handle_admin_message(struct userdata *, DBusMessage *);
static void handle_info_message(struct userdata *, DBusMessage *);
static void handle_action_message(struct userdata *, DBusMessage *);
static void registration_cb(DBusPendingCall *, void *);
static int  register_to_pdp(struct pa_policy_dbusif *, struct userdata *);
static int  signal_status(struct userdata *, uint32_t, uint32_t);



struct pa_policy_dbusif *pa_policy_dbusif_init(struct userdata *u,
                                               const char      *ifnam,
                                               const char      *mypath,
                                               const char      *pdpath,
                                               const char      *pdnam)
{
    pa_module               *m = u->module;
    struct pa_policy_dbusif *dbusif = NULL;
    DBusConnection          *dbusconn;
    DBusError                error;
    char                     polrule[512];
    char                     admrule[512];
    
    dbusif = pa_xnew0(struct pa_policy_dbusif, 1);

    dbus_error_init(&error);
    dbusif->conn = pa_dbus_bus_get(m->core, DBUS_BUS_SYSTEM, &error);

    if (dbusif->conn == NULL || dbus_error_is_set(&error)) {
        pa_log("%s: failed to get SYSTEM Bus: %s: %s",
               __FILE__, error.name, error.message);
        goto fail;
    }

    dbusconn = pa_dbus_connection_get(dbusif->conn);

#if 0
    flags  = DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE;
    result = dbus_bus_request_name(dbusconn, POLICY_DBUS_MYNAME, flags,&error);

    if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER &&
        result != DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER    ) {
        pa_log("%s: D-Bus name request failed: %s: %s",
               __FILE__, error.name, error.message);
        goto fail;
    }
#endif
 
    if (!dbus_connection_add_filter(dbusconn, filter,u, NULL)) {
        pa_log("%s: failed to add filter function", __FILE__);
        goto fail;
    }

    if (!ifnam)
        ifnam = POLICY_DBUS_INTERFACE;

    if (!mypath)
        mypath = POLICY_DBUS_MYPATH;

    if (!pdpath)
        pdpath = POLICY_DBUS_PDPATH;

    if (!pdnam)
        pdnam = POLICY_DBUS_PDNAME;

    snprintf(admrule, sizeof(admrule), "type='signal',sender='%s',path='%s',"
             "interface='%s',member='%s'", ADMIN_DBUS_MANAGER,
             ADMIN_DBUS_PATH, ADMIN_DBUS_INTERFACE, ADMIN_NAME_OWNER_CHANGED);
    dbus_bus_add_match(dbusconn, admrule, &error);

    if (dbus_error_is_set(&error)) {
        pa_log("%s: unable to subscribe name change signals on %s: %s: %s",
               __FILE__, ADMIN_DBUS_INTERFACE, error.name, error.message);
        goto fail;
    }

    snprintf(polrule, sizeof(polrule), "type='signal',interface='%s',"
             "path='%s/%s'", ifnam, pdpath, POLICY_DECISION);
    dbus_bus_add_match(dbusconn, polrule, &error);

    if (dbus_error_is_set(&error)) {
        pa_log("%s: unable to subscribe policy signals on %s: %s: %s",
               __FILE__, ifnam, error.name, error.message);
        goto fail;
    }

    pa_log_info("%s: subscribed policy signals on %s", __FILE__, ifnam);

    dbusif->ifnam   = pa_xstrdup(ifnam);
    dbusif->mypath  = pa_xstrdup(mypath);
    dbusif->pdpath  = pa_xstrdup(pdpath);
    dbusif->pdnam   = pa_xstrdup(pdnam);
    dbusif->admrule = pa_xstrdup(admrule);
    dbusif->polrule = pa_xstrdup(polrule);

    register_to_pdp(dbusif, u);

    return dbusif;

 fail:
    pa_policy_dbusif_done(u);
    dbus_error_free(&error);
    return NULL;
}


void pa_policy_dbusif_done(struct userdata *u)
{
    struct pa_policy_dbusif *dbusif;    
    DBusConnection          *dbusconn;
    
    if (u && (dbusif = u->dbusif)) {
        if (dbusif->conn) {
            dbusconn = pa_dbus_connection_get(dbusif->conn);

            dbus_connection_remove_filter(dbusconn, filter,u);
            dbus_bus_remove_match(dbusconn, dbusif->admrule, NULL);
            dbus_bus_remove_match(dbusconn, dbusif->polrule, NULL);

            pa_dbus_connection_unref(dbusif->conn);
        }

        pa_xfree(dbusif->ifnam);
        pa_xfree(dbusif->mypath);
        pa_xfree(dbusif->pdpath);
        pa_xfree(dbusif->pdnam);
        pa_xfree(dbusif->admrule);
        pa_xfree(dbusif->polrule);

        pa_xfree(dbusif);
    }
}

void pa_policy_dbusif_send_device_state(struct userdata *u, char *state,
                                        char **types, int ntype)
{
    static char             *path = (char *)"/com/nokia/policy/info";

    struct pa_policy_dbusif *dbusif = u->dbusif;
    DBusConnection          *conn   = pa_dbus_connection_get(dbusif->conn);
    DBusMessage             *msg;
    DBusMessageIter          mit;
    DBusMessageIter          dit;
    int                      i;
    int                      sts;

    if (!types || ntype < 1)
        return;

    msg = dbus_message_new_signal(path, dbusif->ifnam, "info");

    if (msg == NULL) {
        pa_log("%s: failed to make new info message", __FILE__);
        goto fail;
    }

    dbus_message_iter_init_append(msg, &mit);

    if (!dbus_message_iter_append_basic(&mit, DBUS_TYPE_STRING, &state) ||
        !dbus_message_iter_open_container(&mit, DBUS_TYPE_ARRAY,"s", &dit)){
        pa_log("%s: failed to build info message", __FILE__);
        goto fail;
    }

    for (i = 0; i < ntype; i++) {
        if (!dbus_message_iter_append_basic(&dit, DBUS_TYPE_STRING,&types[i])){
            pa_log("%s: failed to build info message", __FILE__);
            goto fail;
        }
    }

    dbus_message_iter_close_container(&mit, &dit);

    sts = dbus_connection_send(conn, msg, NULL);

    if (!sts) {
        pa_log("%s: Can't send status message: out of memory", __FILE__);
    }

 fail:
    dbus_message_unref(msg);    /* should cope with NULL msg */
}

static DBusHandlerResult filter(DBusConnection *conn, DBusMessage *msg,
                                void *arg)
{
    struct userdata  *u = arg;

    if (dbus_message_is_signal(msg, ADMIN_DBUS_INTERFACE,
                               ADMIN_NAME_OWNER_CHANGED))
    {
        handle_admin_message(u, msg);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }


    if (dbus_message_is_signal(msg, POLICY_DBUS_INTERFACE, POLICY_INFO)) {
        handle_info_message(u, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    if (dbus_message_is_signal(msg, POLICY_DBUS_INTERFACE, POLICY_ACTIONS)) {
        handle_action_message(u, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void handle_admin_message(struct userdata *u, DBusMessage *msg)
{
    struct pa_policy_dbusif *dbusif;
    char                    *name;
    char                    *before;
    char                    *after;
    int                      success;

    pa_assert(u);
    pa_assert((dbusif = u->dbusif));

    success = dbus_message_get_args(msg, NULL,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_STRING, &before,
                                    DBUS_TYPE_STRING, &after,
                                    DBUS_TYPE_INVALID);

    if (!success || !name) {
        pa_log("Received malformed '%s' message", ADMIN_NAME_OWNER_CHANGED);
        return;
    }

    if (strcmp(name, dbusif->pdnam)) {
        return;
    }

    if (after && strcmp(after, "")) {
        pa_log_debug("policy decision point is up");

        if (!dbusif->regist) {
            register_to_pdp(dbusif, u);
        }
    }


    if (name && before && (!after || !strcmp(after, ""))) {
        pa_log_info("policy decision point is gone");
        dbusif->regist = 0;
    } 
}

static void handle_info_message(struct userdata *u, DBusMessage *msg)
{
    dbus_uint32_t  txid;
    dbus_uint32_t  pid;
    char          *oper;
    char          *group;
    char          *stnam;
    int            success;

    success = dbus_message_get_args(msg, NULL,
                                    DBUS_TYPE_UINT32, &txid,
                                    DBUS_TYPE_STRING, &oper,
                                    DBUS_TYPE_STRING, &group,
                                    DBUS_TYPE_UINT32, &pid,
                                    DBUS_TYPE_STRING, &stnam,
                                    DBUS_TYPE_INVALID);
    if (!success) {
        pa_log("%s: failed to parse message", __FILE__);
        return;
    }

    if (!strcmp(oper, "register")) {

        if (pa_policy_group_find(u, group) == NULL) {
            pa_log_debug("%s: register client (%s|%u) failed: unknown group",
                         __FILE__, group, pid);
        }
        else {
            pa_log_debug("%s: register client (%s|%u|%s)",
                         __FILE__, group, pid, stnam);
            pa_classify_register_pid(u, (pid_t)pid, stnam, group);
        }
        
    }
    else if (!strcmp(oper, "unregister")) {
        pa_log_debug("%s: unregister client (%s|%u)", __FILE__, group, pid);
        pa_classify_unregister_pid(u, (pid_t)pid, stnam);
    }
    else {
        pa_log("%s: invalid operation: '%s'", __FILE__, oper);
    }
}

static void handle_action_message(struct userdata *u, DBusMessage *msg)
{
    static struct actdsc actions[] = {
        { "com.nokia.policy.audio_route" , audio_route_parser  },
        { "com.nokia.policy.volume_limit", volume_limit_parser },
        { "com.nokia.policy.audio_cork"  , audio_cork_parser   },
        { "com.nokia.policy.audio_mute"  , audio_mute_parser   },
        {               NULL             , NULL                }
    };

    struct actdsc   *act;
    dbus_uint32_t    txid;
    char            *actname;
    DBusMessageIter  msgit;
    DBusMessageIter  arrit;
    DBusMessageIter  entit;
    DBusMessageIter  actit;
    int              success = TRUE;

    pa_log_debug("%s: got policy actions", __FILE__);

    dbus_message_iter_init(msg, &msgit);

    if (dbus_message_iter_get_arg_type(&msgit) != DBUS_TYPE_UINT32)
        return;

    dbus_message_iter_get_basic(&msgit, (void *)&txid);

    pa_log_debug("%s: got actions (txid:%d)", __FILE__, txid);

    if (!dbus_message_iter_next(&msgit) ||
        dbus_message_iter_get_arg_type(&msgit) != DBUS_TYPE_ARRAY) {
        success = FALSE;
        goto send_signal;
    }

    dbus_message_iter_recurse(&msgit, &arrit);

    do {
        if (dbus_message_iter_get_arg_type(&arrit) != DBUS_TYPE_DICT_ENTRY) {
            success = FALSE;
            continue;
        }

        dbus_message_iter_recurse(&arrit, &entit);

        do {
            if (dbus_message_iter_get_arg_type(&entit) != DBUS_TYPE_STRING) {
                success = FALSE;
                continue;
            }
            
            dbus_message_iter_get_basic(&entit, (void *)&actname);
            
            if (!dbus_message_iter_next(&entit) ||
                dbus_message_iter_get_arg_type(&entit) != DBUS_TYPE_ARRAY) {
                success = FALSE;
                continue;
            }
            
            dbus_message_iter_recurse(&entit, &actit);
            
            if (dbus_message_iter_get_arg_type(&actit) != DBUS_TYPE_ARRAY) {
                success = FALSE;
                continue;
            }
            
            for (act = actions;   act->name != NULL;   act++) {
                if (!strcmp(actname, act->name))
                    break;
            }
                                    
            if (act->parser == NULL)
                success &= FALSE;
            else
                success &= act->parser(u, &actit);

        } while (dbus_message_iter_next(&entit));

    } while (dbus_message_iter_next(&arrit));

 send_signal:
    signal_status(u, txid, success);
}

static int action_parser(DBusMessageIter *actit, struct argdsc *descs,
                         void *args, int len)
{
    DBusMessageIter  cmdit;
    DBusMessageIter  argit;
    DBusMessageIter  valit;
    struct argdsc   *desc;
    char            *argname;
    void            *argval;
    
    dbus_message_iter_recurse(actit, &cmdit);

    memset(args, 0, len);

    do {
        if (dbus_message_iter_get_arg_type(&cmdit) != DBUS_TYPE_STRUCT)
            return FALSE;

        dbus_message_iter_recurse(&cmdit, &argit);

        if (dbus_message_iter_get_arg_type(&argit) != DBUS_TYPE_STRING)
            return FALSE;

        dbus_message_iter_get_basic(&argit, (void *)&argname);
            
        if (!dbus_message_iter_next(&argit))
            return FALSE;

        if (dbus_message_iter_get_arg_type(&argit) != DBUS_TYPE_VARIANT)
            return FALSE;

        dbus_message_iter_recurse(&argit, &valit);
                    
        for (desc = descs;  desc->name != NULL;  desc++) {
            if (!strcmp(argname, desc->name)) {
                if (desc->offs + (int)sizeof(char *) > len) {
                    pa_log("%s: %s() desc offset %d  is out of range %d",
                           __FILE__, __FUNCTION__, desc->offs, len);
                    return FALSE;
                }
                else {
                    if (dbus_message_iter_get_arg_type(&valit) != desc->type)
                        return FALSE;

                    argval = (char *)args + desc->offs;

                    dbus_message_iter_get_basic(&valit, argval);
                }
                break;
            }
        }

    } while (dbus_message_iter_next(&cmdit));

    return TRUE;
}

static int audio_route_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"type"  , STRUCT_OFFSET(struct argrt, type)  , DBUS_TYPE_STRING },
        {"device", STRUCT_OFFSET(struct argrt, device), DBUS_TYPE_STRING },
        {  NULL  ,            0                       , DBUS_TYPE_INVALID}
    };

    struct argrt args;
    enum pa_policy_route_class class;
    char *target;

    do {
        if (!action_parser(actit, descs, &args, sizeof(args)))
            return FALSE;

        if (args.type == NULL || args.device == NULL)
            return FALSE;

        if (!strcmp(args.type, "sink"))
            class = pa_policy_route_to_sink;
        else if (!strcmp(args.type, "source"))
            class = pa_policy_route_to_source;
        else
            return FALSE;

        target = args.device;

        pa_log_debug("%s: route %s to %s", __FILE__, args.type, target);

        if (pa_policy_group_move_to(u, NULL, class, target) < 0) {
            pa_log("%s: can't route to %s %s", __FILE__, args.type, target);
            return FALSE;
        }

    } while (dbus_message_iter_next(actit));

    return TRUE;
}

static int volume_limit_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"group", STRUCT_OFFSET(struct argvol, group), DBUS_TYPE_STRING },
        {"limit", STRUCT_OFFSET(struct argvol, limit), DBUS_TYPE_STRING },
        {  NULL ,            0                       , DBUS_TYPE_INVALID}
    };

    struct argvol  args;
    char          *grp;
    uint32_t       val;
    char          *end;

    do {
        if (!action_parser(actit, descs, &args, sizeof(args)))
            return FALSE;

        if (args.group == NULL || args.limit == NULL)
            return FALSE;

        grp = args.group;
        val = strtoul(args.limit, &end, 10);

        if (*end || val > 100)
            return FALSE;

        pa_log_debug("%s: volume limit (%s|%d)", __FILE__, grp, val); 
        pa_policy_group_volume_limit(u, grp, val);

    } while (dbus_message_iter_next(actit));

    return TRUE;
}

static int audio_cork_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"group", STRUCT_OFFSET(struct argcork, group), DBUS_TYPE_STRING },
        {"cork" , STRUCT_OFFSET(struct argcork, cork) , DBUS_TYPE_STRING },
        { NULL  ,            0                        , DBUS_TYPE_INVALID}
    };
    
    struct argcork  args;
    char           *grp;
    int             val;
    
    do {
        if (!action_parser(actit, descs, &args, sizeof(args)))
            return FALSE;

        if (args.group == NULL || args.cork == NULL)
            return FALSE;

        grp = args.group;

        if (!strcmp(args.cork, "corked"))
            val = 1;
        else if (!strcmp(args.cork, "uncorked"))
            val = 0;
        else
            return FALSE;
        
        pa_log_debug("%s: cork stream (%s|%d)", __FILE__, grp, val);
        pa_policy_group_cork(u, grp, val);

    } while (dbus_message_iter_next(actit));
    
    return TRUE;
}

static int audio_mute_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"device", STRUCT_OFFSET(struct argmute, device), DBUS_TYPE_STRING },
        {"mute"  , STRUCT_OFFSET(struct argmute, mute)  , DBUS_TYPE_STRING },
        { NULL   ,            0                         , DBUS_TYPE_INVALID}
    };
    
    struct argmute  args;
    char           *device;
    int             val;
    
    do {
        if (!action_parser(actit, descs, &args, sizeof(args)))
            return FALSE;

        if (args.device == NULL || args.mute == NULL)
            return FALSE;

        device = args.device;

        if (!strcmp(args.mute, "muted"))
            val = 1;
        else if (!strcmp(args.mute, "unmuted"))
            val = 0;
        else
            return FALSE;
        
        pa_log_debug("%s: mute device (%s|%d)", __FILE__, device, val);
        pa_source_ext_set_mute(u, device, val);

    } while (dbus_message_iter_next(actit));
    
    return TRUE;
}

static void registration_cb(DBusPendingCall *pend, void *data)
{
    struct userdata *u = (struct userdata *)data;
    DBusMessage     *reply;
    const char      *error_descr;
    int              success;

    if ((reply = dbus_pending_call_steal_reply(pend)) == NULL || u == NULL) {
        pa_log("%s: registartion setting failed: invalid argument", __FILE__);
        return;
    }

    if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
        success = dbus_message_get_args(reply, NULL,
                                        DBUS_TYPE_STRING, &error_descr,
                                        DBUS_TYPE_INVALID);

        if (!success)
            error_descr = dbus_message_get_error_name(reply);

        pa_log_info("%s: registration to policy decision point failed: %s",
                    __FILE__, error_descr);
    }
    else {
        pa_log_info("got reply to registration");

        if (u->dbusif) {
            u->dbusif->regist = 1;
        }
    }

    dbus_message_unref(reply);
}

static int register_to_pdp(struct pa_policy_dbusif *dbusif, struct userdata *u)
{
    DBusConnection  *conn   = pa_dbus_connection_get(dbusif->conn);
    DBusMessage     *msg;
    DBusPendingCall *pend;
    int              success;

    pa_log_info("%s: registering to policy daemon: name='%s' path='%s' if='%s'"
                , __FILE__, dbusif->pdnam, dbusif->pdpath, dbusif->ifnam);

    msg = dbus_message_new_method_call(dbusif->pdnam, dbusif->pdpath,
                                       dbusif->ifnam, "register");

    if (msg == NULL) {
        pa_log("%s: Failed to create D-Dbus message to register",
               __FILE__);
        goto failed;
    }

    success = dbus_connection_send_with_reply(conn, msg, &pend, 1000);
    if (!success) {
        pa_log("%s: Failed to register", __FILE__);
        goto failed;
    }

    success = dbus_pending_call_set_notify(pend, registration_cb, u, NULL);

    if (!success) {
        pa_log("%s: Can't set notification for registartion", __FILE__);
    }

 failed:
    dbus_message_unref(msg);
    return success;
}


static int signal_status(struct userdata *u, uint32_t txid, uint32_t status)
{
    struct pa_policy_dbusif *dbusif = u->dbusif;
    DBusConnection          *conn   = pa_dbus_connection_get(dbusif->conn);
    DBusMessage             *msg;
    char                     path[256];
    int                      ret;

    snprintf(path, sizeof(path), "%s/%s", dbusif->pdpath, POLICY_DECISION);

    pa_log_debug("%s: sending signal to: path='%s', if='%s' member='%s' "
                 "content: txid=%d status=%d", __FILE__, path, dbusif->ifnam,
                 POLICY_STATUS, txid, status);

    msg = dbus_message_new_signal(path, dbusif->ifnam, POLICY_STATUS);

    if (msg == NULL) {
        pa_log("%s: failed to make new status message", __FILE__);
        goto fail;
    }

    ret = dbus_message_append_args(msg,
            DBUS_TYPE_UINT32, &txid,
            DBUS_TYPE_UINT32, &status,
            DBUS_TYPE_INVALID);

    if (!ret) {
        pa_log("%s: Can't build D-Bus status message", __FILE__);
        goto fail;
    }

    ret = dbus_connection_send(conn, msg, NULL);

    if (!ret) {
        pa_log("%s: Can't send status message: out of memory", __FILE__);
        goto fail;
    }

    dbus_message_unref(msg);

    return 0;

 fail:
    dbus_message_unref(msg);    /* should cope with NULL msg */

    return -1;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */

