#ifndef foopolicygroupfoo
#define foopolicygroupfoo

#include <pulse/volume.h>
#include <pulsecore/sink.h>

#include "userdata.h"

#define PA_POLICY_GROUP_HASH_BITS 6
#define PA_POLICY_GROUP_HASH_DIM  (1 << PA_POLICY_GROUP_HASH_BITS)
#define PA_POLICY_GROUP_HASH_MASK (PA_POLICY_GROUP_HASH_DIM - 1)

struct pa_sink_input_list {
    struct pa_sink_input_list *next;
    uint32_t                   index;
    struct pa_sink_input      *sink_input;
};

struct pa_policy_group {
    struct pa_policy_group    *next;
    char                      *name;   /* name of the policy group */
    struct pa_sink            *sink;   /* default sink for the group */
    uint32_t                   index;  /* index of the default sink */
    pa_volume_t                limit;  /* volume limit for the group */
    int                        corked;
    struct pa_sink_input_list *sinpls; /* sink input list */
};

struct pa_policy_groupset {
    struct pa_policy_group    *dflt;     /*  default group */
    struct pa_policy_group    *hash_tbl[PA_POLICY_GROUP_HASH_DIM];
};

struct pa_policy_groupset *pa_policy_groupset_new(struct userdata *);
void pa_policy_groupset_free(struct pa_policy_groupset *);
void pa_policy_groupset_update_default_sink(struct userdata *, uint32_t);
void pa_policy_groupset_create_default_group(struct userdata *);

struct pa_policy_group *pa_policy_group_new(struct userdata *, char*);
void pa_policy_group_free(struct pa_policy_groupset *, char *);
struct pa_policy_group *pa_policy_group_find(struct userdata *, char *);


void pa_policy_group_insert_sink_input(struct userdata *, char *,
                                       struct pa_sink_input *);
void pa_policy_group_remove_sink_input(struct userdata *, uint32_t);

int  pa_policy_group_move_to(struct userdata *, char *, char *);
int  pa_policy_group_cork(struct userdata *u, char *, int);
int  pa_policy_group_volume_limit(struct userdata *, char *, uint32_t);
struct pa_policy_group *pa_policy_group_scan(struct pa_policy_groupset *,
                                             void **);


#endif

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
