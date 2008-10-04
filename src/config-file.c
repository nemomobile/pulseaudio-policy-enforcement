#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
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
    section_max
};

struct groupdef {
    char      *name;
};

struct devicedef {
    char                    *type;
    enum pa_classify_method  method;
    char                    *sink;
    uint32_t                 flags;
};

struct section {
    enum section_type     type;
    union {
        void             *any;
        struct groupdef  *group;
        struct devicedef *device;
    }                     def;
};


static int preprocess_buffer(int, char *, char *);

static int section_header(int, char *, enum section_type *);
static int section_open(struct userdata *, enum section_type,struct section *);
static int section_close(struct userdata *, struct section *);

static int groupdef_parse(int, char *, struct groupdef *);
static int devicedef_parse(int, char *, struct devicedef *);

static int valid_label(char *);


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
                    pa_policy_group_new(u, grdef->name);

                break;

            case section_device:
                devdef = section.def.device;

                if (devicedef_parse(lineno, line, devdef) < 0)
                    sts = 0;

                break;

            default:
                break;

            }
        }
    }

    section_close(u, &section);


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
    int   sts;

    if (grdef == NULL)
        sts = -1;
    else {
        grdef->name = line;
        sts = valid_label(grdef->name) ? 0 : -1;
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

static int valid_label(char *label)
{
    int c;

    if (!isalpha(*label))
        return 0;

    while((c = *label++) != '\0') {
        if (!isalpha(c) && isdigit(c) && c != '-' && c != '_')
            return 0;
    }

    return 1;
}



/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
