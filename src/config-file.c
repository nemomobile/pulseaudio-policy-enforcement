#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>

#ifndef __USE_ISOC99
#define __USE_ISOC99
#include <ctype.h>
#undef __USE_ISOC99
#else
#include <ctype.h>
#endif

#include <pulsecore/pulsecore-config.h>

#include <pulsecore/log.h>

#include "config-file.h"
#include "policy-group.h"
#include "classify.h"

#define DEFAULT_CONFIG_FILE "policy.conf"

enum section_type {
    section_unknown = 0,
    section_group,
    section_device,
    section_stream,
    section_max
};

enum device_class {
    device_unknown = 0,
    device_sink,
    device_source,
    device_max
};

struct groupdef {
    char                    *name;
    char                    *sink;
    char                    *source;
    uint32_t                 flags;
};

struct devicedef {
    enum device_class        class;
    char                    *type;
    char                    *prop;
    enum pa_classify_method  method;
    char                    *arg;
    uint32_t                 flags;
};

struct streamdef {
    char                    *stnam; /* stream name */
    char                    *clnam; /* client's name in pulse audio */
    uid_t                    uid;   /* client's user id */
    char                    *exe;   /* the executable name (i.e. argv[0]) */
    char                    *group; /* group name the stream belong to */
};

struct section {
    enum section_type        type;
    union {
        void             *any;
        struct groupdef  *group;
        struct devicedef *device;
        struct streamdef *stream;
    }                        def;
};


static int preprocess_buffer(int, char *, char *);

static int section_header(int, char *, enum section_type *);
static int section_open(struct userdata *, enum section_type,struct section *);
static int section_close(struct userdata *, struct section *);

static int groupdef_parse(int, char *, struct groupdef *);
static int devicedef_parse(int, char *, struct devicedef *);
static int streamdef_parse(int, char *, struct streamdef *);

static int deviceprop_parse(int, enum device_class,char *, struct devicedef *);
static int valid_label(int, char *);


int pa_policy_parse_config_file(struct userdata *u, const char *cfgfile)
{
#define BUFSIZE 512

    FILE              *f;
    char               cfgpath[PATH_MAX];
    char               buf[BUFSIZE];
    char               line[BUFSIZE];
    int                lineno;
    enum section_type  newsect;
    struct section     section;
    struct groupdef   *grdef;
    struct devicedef  *devdef;
    struct streamdef  *strdef;
    int                sts;

    pa_assert(u);

    if (!cfgfile)
        cfgfile = DEFAULT_CONFIG_FILE;

    pa_policy_file_path(cfgfile, cfgpath, PATH_MAX);
    pa_log_info("%s: policy config file is '%s'", __FILE__, cfgpath);

    if ((f = fopen(cfgpath, "r")) == NULL) {
        pa_log("%s: Can't open config file '%s': %s",
               __FILE__, cfgpath, strerror(errno));
        return 0;
    }

    sts = 1;                    /* assume successful operation */

    memset(&section, 0, sizeof(section));

    for (errno = 0, lineno = 1;  fgets(buf, BUFSIZE, f) != NULL;  lineno++) {
        if (preprocess_buffer(lineno, buf, line) < 0)
            break;

        if (*line == '\0')
            continue;

        if (section_header(lineno, line, &newsect)) {
            if (section_close(u, &section) < 0)
                sts = 0;

            section.type = newsect;

            if (section_open(u, newsect, &section) < 0)
                sts = 0;
        }
        else {
            switch (section.type) {

            case section_group:
                grdef = section.def.group;

                if (groupdef_parse(lineno, line, grdef) < 0)
                    sts = 0;

                break;

            case section_device:
                devdef = section.def.device;

                if (devicedef_parse(lineno, line, devdef) < 0)
                    sts = 0;

                break;

            case section_stream:
                strdef = section.def.stream;

                if (streamdef_parse(lineno, line, strdef) < 0)
                    sts = 0;
                
                break;
                
            default:
                break;

            }
        }
    }

    section_close(u, &section);
    endpwent();

    return sts;
}

static int preprocess_buffer(int lineno, char *inbuf, char *outbuf)
{
    char           c, *p, *q;
    int             quote;
    int             sts = 0;

    for (quote = 0, p = inbuf, q = outbuf;   (c = *p) != '\0';   p++) {
        if (!quote && isblank(c))
            continue;
        
        if (c == '\n' || c == '#')
            break;
        
        if (c == '"') {
            quote ^= 1;
            continue;
        }
        
        if (c < 0x20) {
            pa_log("%s: Illegal character 0x%02x in line %d",
                   __FILE__, c, lineno);
            sts = -1;
            errno = EILSEQ;
            break;
        }
        
        *q++ = c;
    }
    *q = '\0';

    return sts;
}


static int section_header(int lineno, char *line, enum section_type *type)
{
    int is_section;

    if (line[0] != '[')
        is_section = 0;
    else {
        is_section = 1;

        if (!strcmp(line, "[group]"))
            *type = section_group;
        else if (!strcmp(line,"[device]"))
            *type = section_device;
        else if (!strcmp(line, "[stream]"))
            *type = section_stream;
        else {
            *type = section_unknown;
            pa_log("%s: Invalid section type '%s' in line %d",
                   __FILE__, line, lineno);
        }
    }

    return is_section;
}

static int section_open(struct userdata *u, enum section_type type,
                        struct section *sec)
{
    int status;

    if (sec == NULL)
        status = -1;
    else {
        switch (type) {
            
        case section_group:
            sec->def.group = pa_xnew0(struct groupdef, 1);
            status = 0;
            break;
            
        case section_device:
            sec->def.device = pa_xnew0(struct devicedef, 1);
            status = 0;
            break;

        case section_stream:
            sec->def.stream = pa_xnew0(struct streamdef, 1);
            sec->def.stream->uid = -1;
            status = 0;
            break;
            
        default:
            type = section_unknown;
            sec->def.any = NULL;
            status = -1;
            break;
        }

        sec->type = type;
    }

    return status;
}

static int section_close(struct userdata *u, struct section *sec)
{
    struct groupdef  *grdef;
    struct devicedef *devdef;
    struct streamdef *strdef;
    int               status;

    if (sec == NULL)
        status = -1;
    else {
        switch (sec->type) {
            
        case section_group:
            status = 0;
            grdef  = sec->def.group;

            pa_policy_group_new(u, grdef->name, grdef->sink,
                                grdef->source, grdef->flags);

            pa_xfree(grdef->name);
            pa_xfree(grdef->sink);
            pa_xfree(grdef->source);
            pa_xfree(grdef);

            break;
            
        case section_device:
            status = 0;
            devdef = sec->def.device;
            
            switch (devdef->class) {

            case device_sink:
                pa_classify_add_sink(u, devdef->type,
                                     devdef->prop, devdef->method, devdef->arg,
                                     devdef->flags);
                break;

            case device_source:
                pa_classify_add_source(u, devdef->type,
                                       devdef->prop,devdef->method,devdef->arg,
                                       devdef->flags);
                break;

            default:
                break;
            }
            
            pa_xfree(devdef->type);
            pa_xfree(devdef->prop);
            pa_xfree(devdef->arg);
            pa_xfree(devdef);

            break;

        case section_stream:
            status = 0;
            strdef = sec->def.stream;

            pa_classify_add_stream(u, strdef->clnam, strdef->uid, strdef->exe,
                                   strdef->stnam, strdef->group);

            pa_xfree(strdef->stnam);
            pa_xfree(strdef->clnam);
            pa_xfree(strdef->exe);
            pa_xfree(strdef->group);
            pa_xfree(strdef);

            break;
            
        default:
            status = 0;
            break;
        }
        
        sec->type = section_unknown;
        sec->def.any = NULL;
    }

    return status;
}


static int groupdef_parse(int lineno, char *line, struct groupdef *grdef)
{
    int       sts = 0;
    char     *end;
    char     *comma;
    char     *fldef;
    char     *flname;
    int       len;
    uint32_t  flags;

    if (grdef == NULL)
        sts = -1;
    else {
        if (!strncmp(line, "name=", 5)) {
            if (!valid_label(lineno, line+5))
                sts = -1;
            else
                grdef->name = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "sink=", 5)) {
            grdef->sink = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "source=", 7)) {
            grdef->source = pa_xstrdup(line+7);
        }
        else if (!strncmp(line, "flags=", 6)) { 
            fldef = line + 6;
            
            if (fldef[0] == '\0') {
                sts = -1;
                pa_log("%s: missing flag definition in line %d",
                       __FILE__, lineno);
            }
            else {
                sts = 0;

                if (!strcmp(fldef, "client"))
                    flags = PA_POLICY_GROUP_FLAGS_CLIENT;
                else if (!strcmp(fldef, "nopolicy"))
                    flags = PA_POLICY_GROUP_FLAGS_NOPOLICY;
                else {
                    flags = 0;

                    for (flname = fldef;  *flname;  flname += len) {
                        if ((comma = strchr(flname, ',')) == NULL)
                            len = strlen(flname);
                        else {
                            *comma = '\0';
                            len = (comma - flname) + 1;
                        }

                        if (!strcmp(flname, "route_audio"))
                            flags |= PA_POLICY_GROUP_FLAG_ROUTE_AUDIO;
                        else if (!strcmp(flname, "limit_volume"))
                            flags |= PA_POLICY_GROUP_FLAG_LIMIT_VOLUME;
                        else if (!strcmp(flname, "cork_stream"))
                            flags |= PA_POLICY_GROUP_FLAG_CORK_STREAM;
                        else {
                            pa_log("%s: invalid flag '%s' in line %d",
                                   __FILE__, flname, lineno);
                            sts = -1;
                            break;
                        }
                    } /* for */
                }

                if (sts >= 0) {
                    grdef->flags = flags;
                }
            }
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("%s: invalid definition '%s' in line %d",
                       __FILE__, line, lineno);
            }
            else {
                *end = '\0';
                pa_log("%s: invalid key value '%s' in line %d",
                       __FILE__, line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int devicedef_parse(int lineno, char *line, struct devicedef *devdef)
{
    int   sts;
    char *end;

    if (devdef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "type=", 5)) {
            devdef->type = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "sink=", 5)) {
            sts = deviceprop_parse(lineno, device_sink, line+5, devdef);
        }
        else if (!strncmp(line, "source=", 7)) {
            sts = deviceprop_parse(lineno, device_source, line+7, devdef);
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("%s: invalid definition '%s' in line %d",
                       __FILE__, line, lineno);
            }
            else {
                *end = '\0';
                pa_log("%s: invalid key value '%s' in line %d",
                       __FILE__, line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int streamdef_parse(int lineno, char *line, struct streamdef *strdef)
{
    int            sts;
    char          *user;
    struct passwd *pwd;
    uid_t          uid;
    char          *end;

    if (strdef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "name=", 5)) {
            strdef->stnam = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "client=", 7)) {
            strdef->clnam = pa_xstrdup(line+7);
        }
        else if (!strncmp(line, "user=", 5)) {
            user = line+5;
            uid  = strtol(user, &end, 10);

            if (end == user || *end != '\0' || uid < 0) {
                uid = -1;
                setpwent();

                while ((pwd = getpwent()) != NULL) {
                    if (!strcmp(user, pwd->pw_name)) {
                        uid = pwd->pw_uid;
                        break;
                    }
                }

                if (uid < 0) {
                    pa_log("%s: invalid user '%s' in line %d",
                           __FILE__, user, lineno);
                    sts = -1;
                }
            }

            strdef->uid = uid;
        }
        else if (!strncmp(line, "exe=", 4)) {
            strdef->exe = pa_xstrdup(line+4);
        }
        else if (!strncmp(line, "group=", 6)) {
            strdef->group = pa_xstrdup(line+6);
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("%s: invalid definition '%s' in line %d",
                       __FILE__, line, lineno);
            }
            else {
                *end = '\0';
                pa_log("%s: invalid key value '%s' in line %d",
                       __FILE__, line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int deviceprop_parse(int lineno, enum device_class class, char *propdef,
                            struct devicedef *devdef)
{
    char *colon;
    char *at;
    char *prop;
    char *method;
    char *arg;

    if ((colon = strchr(propdef, ':')) == NULL) {
        pa_log("%s: invalid definition '%s' in line %d",
               __FILE__, propdef, lineno);
        return -1;
    }

    *colon = '\0';
    arg    = colon + 1;

    if ((at = strchr(propdef, '@')) == NULL) {
        prop   = "name";
        method = propdef;
    }
    else {
        *at    = '\0';
        prop   = propdef;
        method = at + 1;
    }
    
    if (!strcmp(method, "equals"))
        devdef->method = pa_method_equals;
    else if (!strcmp(method, "startswith"))
        devdef->method = pa_method_startswith;
    else if (!strcmp(method, "matches"))
        devdef->method = pa_method_matches;
    else {
        pa_log("%s: invalid method '%s' in line %d",
               __FILE__, method, lineno);
        return -1;
    }
    
    devdef->class = class;
    devdef->prop  = pa_xstrdup(prop);
    devdef->arg   = pa_xstrdup(arg);
    
    return 0;
}

static int valid_label(int lineno, char *label)
{
    int c;

    if (!isalpha(*label))
        goto invalid;

    while((c = *label++) != '\0') {
        if (!isalpha(c) && isdigit(c) && c != '-' && c != '_')
            goto invalid;
    }

    return 1;

 invalid:
    pa_log("%s: invalid label '%s' in line %d", __FILE__, label, lineno);
    return 0;
}



/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
