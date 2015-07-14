#ifndef foosinkinputextfoo
#define foosinkinputextfoo

#include <stdint.h>
#include <sys/types.h>

#include <pulse/volume.h>
#include <pulsecore/sink-input.h>
#include <pulsecore/sink.h>
#include <pulsecore/core-subscribe.h>


#include "userdata.h"

struct pa_sinp_evsubscr {
    pa_hook_slot    *neew;
    pa_hook_slot    *fixate;
    pa_hook_slot    *put;
    pa_hook_slot    *unlink;
    pa_hook_slot    *cork_state;
    pa_hook_slot    *mute_state;
};

enum pa_sink_input_ext_state {
    PA_SINK_INPUT_EXT_STATE_NONE    = 0,
    PA_SINK_INPUT_EXT_STATE_USER    = 1 << 0,
    PA_SINK_INPUT_EXT_STATE_POLICY  = 1 << 1
};

struct pa_sink_input_ext {
    struct {
        int route;
        int mute;
        uint32_t cork_state;
        bool ignore_cork_state_change;
        uint32_t mute_state;
        bool ignore_mute_state_change;
    }                local;     /* local policies */
};

struct pa_sinp_evsubscr *pa_sink_input_ext_subscription(struct userdata *);
void  pa_sink_input_ext_subscription_free(struct pa_sinp_evsubscr *);
void  pa_sink_input_ext_discover(struct userdata *);
/* Go through all othermedia streams and re-classify them. */
void  pa_sink_input_ext_rediscover(struct userdata *u);
struct pa_sink_input_ext *pa_sink_input_ext_lookup(struct userdata *,
                                                   struct pa_sink_input *);
int   pa_sink_input_ext_set_policy_group(struct pa_sink_input *, const char *);
const char *pa_sink_input_ext_get_policy_group(struct pa_sink_input *);
const char *pa_sink_input_ext_get_name(struct pa_sink_input *);
int   pa_sink_input_ext_set_volume_limit(struct userdata *u, struct pa_sink_input *, pa_volume_t);
bool pa_sink_input_ext_cork(struct userdata *u, pa_sink_input *si, bool cork);
bool pa_sink_input_ext_mute(struct userdata *u, pa_sink_input *si, bool mute);

#endif

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
