#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/log.h>
#include <pulsecore/client.h>
#include <pulsecore/sink-input.h>
#include <pulsecore/source-output.h>

#include "classify.h"
#include "client-ext.h"
#include "sink-input-ext.h"
#include "source-output-ext.h"



static char *find_group_for_client(struct userdata *,
                                   struct pa_client *, char *);
#if 0
static char *arg_dump(int, char **, char *, size_t);
#endif

static void  pid_hash_free(struct pa_classify_pid_hash **);
static void  pid_hash_insert(struct pa_classify_pid_hash **, pid_t,
                             const char *, const char *);
static void  pid_hash_remove(struct pa_classify_pid_hash **, pid_t,
                             const char *);
static char *pid_hash_get_group(struct pa_classify_pid_hash **, pid_t,
                                const char *);
static struct pa_classify_pid_hash
            *pid_hash_find(struct pa_classify_pid_hash **, pid_t, const char *,
                           struct pa_classify_pid_hash **);

static void streams_free(struct pa_classify_stream_def *);
static void streams_add(struct pa_classify_stream_def **, char *, uid_t,
                        char *, char *, char *);
static char *streams_get_group(struct pa_classify_stream_def **, char *,
                               uid_t, char *, char *);
static struct pa_classify_stream_def
            *streams_find(struct pa_classify_stream_def **, char *, uid_t,
                          char *, char *, struct pa_classify_stream_def **);

static void devices_free(struct pa_classify_device *);
static void devices_add(struct pa_classify_device **, char *,
                        enum pa_classify_method, char *, uint32_t);
static int devices_classify(struct pa_classify_device_def *,
                            uint32_t, char *, char *, int);
static int devices_is_typeof(struct pa_classify_device_def *, char *, char *);

int method_equals(const char *, union pa_classify_arg *);
int method_startswith(const char *, union pa_classify_arg *);
int method_matches(const char *, union pa_classify_arg *);


struct pa_classify *pa_classify_new(struct userdata *u)
{
    struct pa_classify *cl;

    cl = pa_xnew0(struct pa_classify, 1);

    cl->sinks   = pa_xnew0(struct pa_classify_device, 1);
    cl->sources = pa_xnew0(struct pa_classify_device, 1);

    return cl;
}

void pa_classify_free(struct pa_classify *cl)
{
    if (cl) {
        pid_hash_free(cl->streams.pid_hash);
        streams_free(cl->streams.defs);
        devices_free(cl->sinks);
        devices_free(cl->sources);

        pa_xfree(cl);
    }
}

void pa_classify_add_sink(struct userdata *u, char *type,
                          enum pa_classify_method method, char *sinkid,
                          uint32_t flags)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert((classify = u->classify));
    pa_assert(classify->sinks);
    pa_assert(type);
    pa_assert(sinkid);

    devices_add(&classify->sinks, type, method, sinkid, flags);
}

void pa_classify_add_source(struct userdata *u, char *type,
                            enum pa_classify_method method, char *sourceid,
                            uint32_t flags)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert((classify = u->classify));
    pa_assert(classify->sources);
    pa_assert(type);
    pa_assert(sourceid);

    devices_add(&classify->sources, type, method, sourceid, flags);
}

void pa_classify_add_stream(struct userdata *u, char *clnam, uid_t uid,
                            char *exe, char *stnam, char *group)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert((classify = u->classify));

    if ((stnam || clnam || uid != (uid_t)-1 || exe) && group) {
        streams_add(&classify->streams.defs, clnam, uid, exe, stnam, group);
    }
}

void pa_classify_register_pid(struct userdata *u, pid_t pid, char *stnam,
                              char *group)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert((classify = u->classify));

    if (pid && group) {
        pid_hash_insert(classify->streams.pid_hash, pid, stnam, group);
    }
}

void pa_classify_unregister_pid(struct userdata *u, pid_t pid, char *stnam)
{
    struct pa_classify *classify;
    
    pa_assert(u);
    pa_assert((classify = u->classify));

    if (pid) {
        pid_hash_remove(classify->streams.pid_hash, pid, stnam);
    }
}

char *pa_classify_sink_input(struct userdata *u, struct pa_sink_input *sinp)
{
    struct pa_client     *client;
    char                 *stnam;  /* stream name */
    char                 *group;

    pa_assert(u);
    pa_assert(sinp);

    stnam = pa_sink_input_ext_get_name(sinp);
    group = find_group_for_client(u, client, stnam);

    return group;
}

char *pa_classify_source_output(struct userdata *u,
                                struct pa_source_output *sout)
{
    struct pa_client     *client;
    char                 *stnam;  /* stream name */
    char                 *group;

    pa_assert(u);
    pa_assert(sout);

    stnam = pa_source_output_ext_get_name(sout);
    group = find_group_for_client(u, client, stnam);

    return group;
}

int pa_classify_sink(struct userdata *u, uint32_t sidx, char *name,
                     char *buf, int len)
{
    struct pa_classify *classify;
    struct pa_classify_device *sinks;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert((classify = u->classify));
    pa_assert((sinks = classify->sinks));
    pa_assert((defs = sinks->defs));

    return devices_classify(defs, sidx, name, buf, len);
}

int pa_classify_source(struct userdata *u, uint32_t sidx, char *name,
                       char *buf, int len)
{
    struct pa_classify *classify;
    struct pa_classify_device *sources;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert((classify = u->classify));
    pa_assert((sources = classify->sources));
    pa_assert((defs = sources->defs));

    return devices_classify(defs, sidx, name, buf, len);
}

int pa_classify_is_sink_typeof(struct userdata *u, char *sink, char *type)
{
    struct pa_classify *classify;
    struct pa_classify_device *sinks;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert((classify = u->classify));
    pa_assert((sinks = classify->sinks));
    pa_assert((defs = sinks->defs));

    if (!sink || !type)
        return FALSE;

    return devices_is_typeof(defs, sink, type);
}


int pa_classify_is_source_typeof(struct userdata *u, char *source, char *type)
{
    struct pa_classify *classify;
    struct pa_classify_device *sources;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert((classify = u->classify));
    pa_assert((sources = classify->sources));
    pa_assert((defs = sources->defs));

    if (!source || !type)
        return FALSE;

    return devices_is_typeof(defs, source, type);
}


static char *find_group_for_client(struct userdata  *u,
                                   struct pa_client *client,
                                   char             *stnam)
{
    struct pa_classify *classify;
    struct pa_classify_pid_hash **hash;
    struct pa_classify_stream_def **defs;
    pid_t    pid   = 0;           /* client processs PID */
    char    *clnam = (char *)"";  /* client's name in PA */
    uid_t    uid   = (uid_t)-1;   /* client process user ID */
    char    *exe   = (char *)"";  /* client's binary path */
    char    *group = NULL;

    assert(u);
    pa_assert((classify = u->classify));

    hash = classify->streams.pid_hash;
    defs = &classify->streams.defs;

    if (client == NULL)
        group = streams_get_group(defs, clnam, uid, exe, stnam);
    else {
        pid = pa_client_ext_pid(client);

        if ((group = pid_hash_get_group(hash, pid, stnam)) == NULL) {
            clnam = pa_client_ext_name(client);
            uid   = pa_client_ext_uid(client);
            exe   = pa_client_ext_exe(client);
            
            group = streams_get_group(defs, clnam, uid, exe, stnam);
        }
    }

    if (group == NULL)
        group = (char *)PA_POLICY_DEFAULT_GROUP_NAME;

    pa_log_debug("%s (%s|%s|%d|%d|%s) => %s", __FUNCTION__,
                 clnam?clnam:"<null>", stnam?stnam:"<null>",
                 pid, uid, exe?exe:"<null>", group?group:"<null>");

    return group;
}

#if 0
static char *arg_dump(int argc, char **argv, char *buf, size_t len)
{
    char *p = buf;
    int   i, l;
    
    if (argc <= 0 || argv == NULL)
        snprintf(buf, len, "0 <null>");
    else {
        l = snprintf(p, len, "%d", argc);
        
        p   += l;
        len -= l;
        
        for (i = 0;  i < argc && len > 0;  i++) {
            l = snprintf(p, len, " [%d]=%s", i, argv[i]);
            
            p   += l;
            len -= l;
        }
    }
    
    return buf;
}
#endif

static void pid_hash_free(struct pa_classify_pid_hash **hash)
{
    struct pa_classify_pid_hash *st;
    int i;

    assert(hash);

    for (i = 0;   i < PA_POLICY_PID_HASH_MAX;   i++) {
        while ((st = hash[i]) != NULL) {
            hash[i] = st->next;

            pa_xfree(st->stnam);
            pa_xfree(st->group);

            pa_xfree(st);
        }
    }
}

static void pid_hash_insert(struct pa_classify_pid_hash **hash, pid_t pid,
                            const char *stnam, const char *group)
{
    struct pa_classify_pid_hash *st;
    struct pa_classify_pid_hash *prev;

    pa_assert(hash);
    pa_assert(group);


    if ((st = pid_hash_find(hash, pid, stnam, &prev)) != NULL) {
        pa_xfree(st->group);
        st->group = pa_xstrdup(group);
    }
    else {
        st  = pa_xnew0(struct pa_classify_pid_hash, 1);

        st->next  = NULL;
        st->pid   = pid;
        st->stnam = stnam ? pa_xstrdup(stnam) : NULL;
        st->group = pa_xstrdup(group);

        prev->next = st;
    }
}

static void pid_hash_remove(struct pa_classify_pid_hash **hash,
                            pid_t pid, const char *stnam)
{
    struct pa_classify_pid_hash *st;
    struct pa_classify_pid_hash *prev;

    pa_assert(hash);

    if ((st = pid_hash_find(hash, pid, stnam, &prev)) != NULL) {
        prev->next = st->next;

        pa_xfree(st->stnam);
        pa_xfree(st->group);
        
        pa_xfree(st);
    }
}

static char *pid_hash_get_group(struct pa_classify_pid_hash **hash,
                                pid_t pid, const char *stnam)
{
    struct pa_classify_pid_hash *st;
    char *group;

    pa_assert(hash);
 
    if (!pid || (st = pid_hash_find(hash, pid, stnam, NULL)) == NULL)
        group = NULL;
    else
        group = st->group;

    return group;
}

static struct
pa_classify_pid_hash *pid_hash_find(struct pa_classify_pid_hash **hash,
                                    pid_t pid, const char *stnam,
                                    struct pa_classify_pid_hash **prev_ret)
{
    struct pa_classify_pid_hash *st;
    struct pa_classify_pid_hash *prev;
    int                          idx;

    idx = pid & PA_POLICY_PID_HASH_MASK;

    for (prev = (struct pa_classify_pid_hash *)&hash[idx];
         (st = prev->next) != NULL;
         prev = prev->next)
    {
        if (pid && pid == st->pid) {
            if ((!stnam && !st->stnam) ||
                ( stnam &&  st->stnam && !strcmp(stnam,st->stnam)))
                break;
        }
    }

    if (prev_ret)
        *prev_ret = prev;

#if 0
    pa_log_debug("%s(%d,'%s') => %p", __FUNCTION__,
                 pid, stnam?stnam:"<null>", st);
#endif

    return st;
}

static void streams_free(struct pa_classify_stream_def *defs)
{
    struct pa_classify_stream_def *stream;
    struct pa_classify_stream_def *next;

    for (stream = defs;  stream;  stream = next) {
        next = stream->next;

        pa_xfree(stream->exe);
        pa_xfree(stream->clnam);
        pa_xfree(stream->stnam);
        pa_xfree(stream->group);

        pa_xfree(stream);
    }
}

static void streams_add(struct pa_classify_stream_def **defs, char *clnam,
                        uid_t uid, char *exe, char *stnam, char *group)
{
    struct pa_classify_stream_def *d;
    struct pa_classify_stream_def *prev;

    pa_assert(defs);
    pa_assert(group);

    if ((d = streams_find(defs, clnam, uid, exe, stnam, &prev)) != NULL) {
        pa_log_info("%s: redefinition of stream", __FILE__);
        pa_xfree(d->group);
    }
    else {
        d = pa_xnew0(struct pa_classify_stream_def, 1);
        
        d->uid   = uid;
        d->exe   = exe   ? pa_xstrdup(exe)   : NULL;
        d->clnam = clnam ? pa_xstrdup(clnam) : NULL;
        d->stnam = stnam ? pa_xstrdup(stnam) : NULL; 
        
        prev->next = d;

        pa_log_debug("stream added (%d|%s|%s|%s)", uid, exe?exe:"<null>",
                     clnam?clnam:"<null>", stnam?stnam:"<null>");
    }

    d->group = pa_xstrdup(group);
}

static char *streams_get_group(struct pa_classify_stream_def **defs,
                               char *clnam, uid_t uid, char *exe, char *stnam)
{
    struct pa_classify_stream_def *d;
    char *group;

    pa_assert(defs);

    if ((d = streams_find(defs, clnam, uid, exe, stnam, NULL)) == NULL)
        group = NULL;
    else
        group = d->group;

    return group;
}

static struct pa_classify_stream_def *
streams_find(struct pa_classify_stream_def **defs, char *clnam, uid_t uid,
             char *exe, char *stnam, struct pa_classify_stream_def **prev_ret)
{
#define STRING_MATCH_OF(m) (!d->m || (m && d->m && !strcmp(m, d->m)))
#define ID_MATCH_OF(m)      (d->m == -1 || m == d->m)

    struct pa_classify_stream_def *prev;
    struct pa_classify_stream_def *d;

    for (prev = (struct pa_classify_stream_def *)defs;
         (d = prev->next) != NULL;
         prev = prev->next)
    {

        if (STRING_MATCH_OF(clnam) &&
            ID_MATCH_OF(uid)       &&
            STRING_MATCH_OF(exe)   &&
            STRING_MATCH_OF(stnam)   )
            break;

    }

    if (prev_ret)
        *prev_ret = prev;

#if 0
    pa_log_debug("%s('%s',%d,'%s','%s') => %p", __FUNCTION__,
                 clnam?clnam:"<null>", uid, exe?exe:"<null>",
                 stnam?stnam:"<null>", d);
#endif

    return d;

#undef STRING_MATCH_OF
#undef ID_MATCH_OF
}

static void devices_free(struct pa_classify_device *sinks)
{
    struct pa_classify_device_def *d;

    if (sinks) {
        for (d = sinks->defs;  d->type;  d++) {
            if (d->method == method_matches)
                regfree(&d->dev.rexp);
            else
                pa_xfree((void *)d->dev.name);
        }

        pa_xfree(sinks);
    }
}

static void devices_add(struct pa_classify_device **p_devices, char *type,
                        enum pa_classify_method method, char *name,
                        uint32_t flags)
{
    struct pa_classify_device *devs;
    struct pa_classify_device_def *d;
    size_t newsize;

    pa_assert(p_devices);
    pa_assert((devs = *p_devices));

    newsize = sizeof(*devs) + sizeof(devs->defs[0]) * (devs->ndef + 1);

    devs = *p_devices = pa_xrealloc(devs, newsize);

    d = devs->defs + devs->ndef;

    memset(d+1, 0, sizeof(devs->defs[0]));

    d->type  = pa_xstrdup(type);
    d->sidx  = PA_IDXSET_INVALID;
    d->flags = flags;

    switch (method) {

    case pa_method_equals:
        d->dev.name = pa_xstrdup(name);
        d->method = method_equals;
        break;

    case pa_method_startswith:
        d->dev.name = pa_xstrdup(name);
        d->method = method_startswith;
        break;

    case pa_method_matches:
        if (regcomp(&d->dev.rexp, name, 0) == 0) {
            d->method = method_matches;
            break;
        }
        /* intentional fall trough */

    default:
        pa_log("%s: invalid device definition %s", __FUNCTION__, type);
        memset(d, 0, sizeof(*d));
        return;
    }

    devs->ndef++;

    pa_log_info("device '%s' added", type);
}

static int devices_classify(struct pa_classify_device_def *defs, uint32_t sidx,
                            char *name, char *buf, int len)
{
    struct pa_classify_device_def *d;
    int         i;
    char       *p;
    char       *e;
    const char *s;

    pa_assert(buf);
    pa_assert(len > 0);
    pa_assert(sidx != PA_IDXSET_INVALID);

    e = (p = buf) + len;
    p[0] = '\0';
    s = "";
        
    for (d = defs, i = 0;  d->type;  d++) {
        if ((name != NULL && d->method(name, &d->dev)) ||
            (name == NULL && sidx == d->sidx))
        {
            p += snprintf(p, (size_t)(e-p), "%s%s", s, d->type);
            s  = " ";
            
            if (p > e) {
                pa_log("%s: %s() buffer overflow", __FILE__, __FUNCTION__);
                *buf = '\0';
                p = e;
                break;
            }
            
            d->sidx = name ? sidx : PA_IDXSET_INVALID;
        }
    }

    return (e - p);
}

static int devices_is_typeof(struct pa_classify_device_def *defs,
                             char *device, char *type)
{
    struct pa_classify_device_def *d;

    for (d = defs;  d->type;  d++) {
        if (!strcmp(type, d->type) && d->method(device, &d->dev))
            return TRUE;
    }

    return FALSE;
}

int method_equals(const char *name, union pa_classify_arg *sink)
{
    int found;

    if (!name || !sink || !sink->name)
        found = FALSE;
    else
        found = !strcmp(name, sink->name);

    return found;
}

int method_startswith(const char *name, union pa_classify_arg *sink)
{
    int found;

    if (!name || !sink || !sink->name)
        found = FALSE;
    else
        found = !strncmp(name, sink->name, strlen(sink->name));

    return found;
}

int method_matches(const char *name, union pa_classify_arg *sink)
{
#define MAX_MATCH 5

    regmatch_t m[MAX_MATCH];
    regoff_t   end;
    int        found;
    
    found = FALSE;

    if (name && sink) {
        if (regexec(&sink->rexp, name, MAX_MATCH, m, 0) == 0) {
            end = strlen(name);

            if (m[0].rm_so == 0 && m[0].rm_eo == end && m[1].rm_so == -1)
                found = TRUE;
        }  
    }


    return found;

#undef MAX_MATCH
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
