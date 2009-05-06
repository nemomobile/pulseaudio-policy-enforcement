#ifndef fooclassifyfoo
#define fooclassifyfoo

#include <sys/types.h>
#include <regex.h>

#include "userdata.h"

#define PA_POLICY_PID_HASH_BITS  6
#define PA_POLICY_PID_HASH_MAX   (1 << PA_POLICY_PID_HASH_BITS)
#define PA_POLICY_PID_HASH_MASK  (PA_POLICY_PID_HASH_MAX - 1)

/* flags */
#define PA_POLICY_DISABLE_NOTIFY (1UL << 0)

struct pa_sink;
struct pa_source;
struct pa_sink_input;
struct pa_sink_input_new_data;
struct pa_card;

enum pa_classify_method {
    pa_method_unknown = 0,
    pa_method_min = pa_method_unknown,
    pa_method_equals,
    pa_method_startswith,
    pa_method_matches,
    pa_method_max
};

union pa_classify_arg {
    const char *string;
    regex_t     rexp;
};

struct pa_classify_pid_hash {
    struct pa_classify_pid_hash *next;
    pid_t                        pid;   /* process id (or parent process id)*/
    char                        *stnam; /* stream's name, if any */
    char                        *group; /* policy group name */
};

struct pa_classify_stream_def {
    struct pa_classify_stream_def *next;
                                          /* for stream classification */
    char                          *prop;  /*   stream property */
    int                          (*method)(const char *,
                                           union pa_classify_arg *);
    union pa_classify_arg          arg;   /*   argument */
    uid_t                          uid;   /* user id, if any */
    char                          *exe;   /* exe name, if any */
    char                          *clnam; /* client name, if any */
    char                          *group; /* policy group name */
};

struct pa_classify_stream {
    struct pa_classify_pid_hash   *pid_hash[PA_POLICY_PID_HASH_MAX];
    struct pa_classify_stream_def *defs;
};

struct pa_classify_device_data {
    uint32_t                         flags; /* PA_POLICY_DISABLE_NOTIFY, etc */
};

struct pa_classify_device_def {
    const char                      *type;  /* device type, e.g. ihf */
                                            /* for classification */
    char                            *prop;  /*   sink/source property */
    int                            (*method)(const char *,
                                             union pa_classify_arg *);
    union pa_classify_arg            arg;   /*   argument */
    struct pa_classify_device_data   data;  /* data associated with device */
};

struct pa_classify_device {
    int                              ndef;
    struct pa_classify_device_def    defs[1];
};

struct pa_classify_card_data {
    char                        *profile; /* name of profile */
    uint32_t                     flags;   /* PA_POLICY_DISABLE_NOTIFY, etc */
};

struct pa_classify_card_def {
    const char                  *type; /* handled device name, e.g ihf */
    int                        (*method)(const char *,union pa_classify_arg *);
    union pa_classify_arg        arg;
    struct pa_classify_card_data data; /* data associated with device 'type' */
};

struct pa_classify_card {
    int                          ndef;
    struct pa_classify_card_def  defs[1];
};

struct pa_classify {
    struct pa_classify_stream    streams;
    struct pa_classify_device   *sinks;
    struct pa_classify_device   *sources;
    struct pa_classify_card     *cards;
};


struct pa_classify *pa_classify_new(struct userdata *);
void  pa_classify_free(struct pa_classify *);
void  pa_classify_add_sink(struct userdata *, char *, char *,
                           enum pa_classify_method, char *, uint32_t);
void  pa_classify_add_source(struct userdata *, char *, char *,
                             enum pa_classify_method, char *, uint32_t);
void  pa_classify_add_card(struct userdata *, char *,
                           enum pa_classify_method, char *, char *, uint32_t);
void pa_classify_add_stream(struct userdata *, char *, enum pa_classify_method,
                            char *, char *, uid_t, char *, char *);

void  pa_classify_register_pid(struct userdata *, pid_t, char *, char *);
void  pa_classify_unregister_pid(struct userdata *, pid_t, char *);

char *pa_classify_sink_input(struct userdata *, struct pa_sink_input *);
char *pa_classify_sink_input_by_data(struct userdata *,
                                     struct pa_sink_input_new_data *);
char *pa_classify_source_output(struct userdata *, struct pa_source_output *);
char *pa_classify_source_output_by_data(struct userdata *,
                                        struct pa_source_output_new_data *);

int   pa_classify_sink(struct userdata *, struct pa_sink *,
                       uint32_t, uint32_t, char *, int);
int   pa_classify_source(struct userdata *, struct pa_source *,
                         uint32_t, uint32_t, char *, int);
int   pa_classify_card(struct userdata *, struct pa_card *,
                       uint32_t, uint32_t, char *, int);

int   pa_classify_is_sink_typeof(struct userdata *, struct pa_sink *, char *,
                                 struct pa_classify_device_data **);
int   pa_classify_is_source_typeof(struct userdata *, struct pa_source *,
                                   char *, struct pa_classify_device_data **);
int   pa_classify_is_card_typeof(struct userdata *, struct pa_card *,
                                 char *, struct pa_classify_card_data **);


#endif


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
