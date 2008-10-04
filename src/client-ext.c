#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <pulse/def.h>

#include "userdata.h"
#include "client-ext.h"

static void handle_client_events(pa_core *, pa_subscription_event_type_t,
				 uint32_t, void *);

static char *client_ext_dump(struct pa_client *, char *, int);


pa_subscription *pa_client_ext_subscription(struct userdata *u)
{
    pa_subscription *subscr;
    
    pa_assert(u->core);
    
    subscr = pa_subscription_new(u->core, 1 << PA_SUBSCRIPTION_EVENT_CLIENT,
                                 handle_client_events, (void *)u);
    
    return subscr;
}

char *pa_client_ext_name(struct pa_client *client)
{
    const char *name;

    assert(client);

    name = pa_proplist_gets(client->proplist, PA_PROP_APPLICATION_NAME);

    return (char *)name;
}

char *pa_client_ext_id(struct pa_client *client)
{
    const char *id;

    assert(client);

    id = pa_proplist_gets(client->proplist, PA_PROP_APPLICATION_ID);

    return (char *)id;
}

pid_t pa_client_ext_pid(struct pa_client *client)
{
    const char *pidstr;
    pid_t       pid;
    char       *e;

    assert(client);

    pid = 0;
    pidstr = pa_proplist_gets(client->proplist,PA_PROP_APPLICATION_PROCESS_ID);

    if (pidstr != NULL) {
        pid = strtoul(pidstr, &e, 10);

        if (*e != '\0')
            pid = 0;
    }

    return pid;
}

uid_t pa_client_ext_uid(struct pa_client *client)
{
    const char *uidstr;
    uid_t       uid;
    char       *e;

    assert(client);

    uid = 0;
    uidstr = pa_proplist_gets(client->proplist,
                              PA_PROP_APPLICATION_PROCESS_USER);

    if (uidstr != NULL) {
        uid = strtoul(uidstr, &e, 10);

        if (*e != '\0')
            uid = 0;
    }

    return uid;
}

char *pa_client_ext_exe(struct pa_client *client)
{
    const char *exe;

    assert(client);

    exe = pa_proplist_gets(client->proplist,
                           PA_PROP_APPLICATION_PROCESS_BINARY);

    return (char *)exe;
}

char *pa_client_ext_args(struct pa_client *client)
{
    const char *args;

    assert(client);

    args = pa_proplist_gets(client->proplist,PA_PROP_APPLICATION_PROCESS_ARGS);

    return (char *)args;
}

static void handle_client_events(pa_core *c,pa_subscription_event_type_t t,
				 uint32_t idx, void *userdata)
{
    struct userdata  *udata  = userdata;
    uint32_t          et     = t & PA_SUBSCRIPTION_EVENT_TYPE_MASK;
    struct pa_client *client;
    char              buf[1024];
    
    pa_assert(udata);
    
    switch (et) {
        
    case PA_SUBSCRIPTION_EVENT_NEW:
        if ((client = pa_idxset_get_by_index(c->clients, idx)) != NULL) {
            pa_log_debug("new client (idx=%d) %s", idx,
                         client_ext_dump(client, buf, sizeof(buf)));
        }
        break;
        
    case PA_SUBSCRIPTION_EVENT_CHANGE:
        if ((client = pa_idxset_get_by_index(c->clients, idx)) != NULL) {
            
            pa_log_debug("change client (idx=%d) %s", idx,
                         client_ext_dump(client, buf, sizeof(buf)));
        }
        break;
        
    case PA_SUBSCRIPTION_EVENT_REMOVE:
        pa_log_debug("client removed (idx=%d)", idx);
        break;
        
    default:
        pa_log("%s: unknown client event type %d", __FILE__, et);
        break;
    }
    
}

static void client_ext_set_args(struct pa_client *client)
{
#if 0
    char  path[256];
    char  args[ARG_MAX];
    int   argc;
    char *argv[1024];
    int   fd, len;
    char *p, *e;
    int   i, offs;
    
    snprintf(path, sizeof(path), "/proc/%d/cmdline", ext->pid);
    
    if ((fd = open(path, O_RDONLY)) < 0) {
        pa_log("%s: Can't obtain command line", __FILE__);
        return;
    }
    
    for (;;) {
        if ((len = read(fd, args, sizeof(args)-1)) < 0) {
            if (errno == EINTR)
                continue;
            else
                return;
        }
        
        args[len] = '\0';
        
        break;
    }
    
    for (e = (p = args) + len, argc = 0;   argc < 1024 && p < e;   argc++) {
        argv[argc] = p;
        
        while (*p++ && p < e)
            ;
    }
    
    p = pa_xmalloc((argc * sizeof(char *)) + len);
    
    memcpy(p, argv, (argc * sizeof(char *)));
    memcpy(p + (argc * sizeof(char *)), args, len);
    
    ext->argc = argc;
    ext->argv = (char **)p;
    
    offs = (p + (argc * sizeof(char *))) - args;
    
    for (i = 0;  i < argc;  i++)
        ext->argv[i] += offs;
#endif
}


static char *client_ext_dump(struct pa_client *client, char *buf, int len)
{
    const char  *name;
    const char  *id;
    pid_t        pid;
    uid_t        uid;
    const char  *exe;
    const char  *args;

    if (client == NULL)
        *buf = '\0';
    else {
        name = pa_client_ext_name(client);
        id   = pa_client_ext_id(client);
        pid  = pa_client_ext_pid(client);
        uid  = pa_client_ext_uid(client);
        exe  = pa_client_ext_exe(client);
        args = pa_client_ext_args(client);

        if (!name)  name = "<noname>";
        if ( !id )  id   = "<noid>";
        if (!exe )  exe  = "<noexe>";
        if (!args)  args = "<noargs>";
     
        snprintf(buf, len, "(%s|%s|%d|%d|%s|%s)", name,id, pid, uid, exe,args);
    }
    
    return buf;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
