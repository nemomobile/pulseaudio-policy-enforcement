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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/log.h>

#include "config-file.h"
#include "policy-group.h"
#include "classify.h"

#define DEFAULT_CONFIG_FILE "policy.conf"

enum section_type {
    section_unknown = 0,
    section_groups,
    section_device,
    section_stream,
    section_max
};

struct groupdef {
    char                     *name;
    uint32_t                 flags;
};

struct devicedef {
    char                    *type;
    enum pa_classify_method  method;
    char                    *sink;
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

    sts = 1;

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

            case section_groups:
                grdef = section.def.group;

                if (groupdef_parse(lineno, line, grdef) < 0)
                    sts = 0;
                else
                    pa_policy_group_new(u, grdef->name, grdef->flags);

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

        if (!strcmp(line, "[groups]"))
            *type = section_groups;
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
            
        case section_groups:
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
            
        case section_groups:
            status = 0;
            grdef  = sec->def.group;

            pa_xfree(grdef);

            break;
            
        case section_device:
            status = 0;
            devdef = sec->def.device;
            
            pa_classify_add_device(u, devdef->type, devdef->method,
                                   devdef->sink, devdef->flags); 
            
            pa_xfree(devdef->type);
            pa_xfree(devdef->sink);
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
    int       sts;
    char     *equal;
    char     *comma;
    char     *name;
    char     *fldef;
    char     *flname;
    int       len;
    uint32_t  flags;

    if (grdef == NULL)
        sts = -1;
    else {
        if ((equal = strchr(line, '=')) == NULL) {
            pa_log("%s: invalid definition '%s' in line %d",
                   __FILE__, line, lineno);
            sts = -1;
        }
        else {
            *equal = '\0';
            name  = line;
            fldef = equal + 1;
            
            if (!valid_label(lineno, name))
                sts = -1;
            else if (fldef[0] == '\0') {
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
                    grdef->name  = line;
                    grdef->flags = flags;
                }
            }
        }
    }

    return sts;
}

static int devicedef_parse(int lineno, char *line, struct devicedef *devdef)
{
    int   sts;
    char *end;
    char *colon;
    char *method;

    if (devdef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "type=", 5)) {
            devdef->type = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "sink=", 5)) {
            if ((colon = strchr(line+5, ':')) == NULL) {
                sts = -1;
                pa_log("%s: invalid definition '%s' in line %d",
                       __FILE__, line+5, lineno);
            }
            else {
                *colon = '\0';
                method = line+5;

                devdef->sink = pa_xstrdup(colon+1);

                if (!strcmp(method, "equals"))
                    devdef->method = pa_method_equals;
                else if (!strcmp(method, "startswith"))
                    devdef->method = pa_method_startswith;
                else if (!strcmp(method, "matches"))
                    devdef->method = pa_method_matches;
                else {
                    sts = -1;

                    pa_log("%s: invalid method '%s' in line %d",
                           __FILE__, method, lineno);
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
