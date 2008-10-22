#ifndef foosinkextfoo
#define foosinkextfoo

#include "userdata.h"

struct pa_sink;

struct pa_sink_evsubscr {
    pa_hook_slot    *put;
    pa_hook_slot    *unlink;
};

struct pa_sink_evsubscr *pa_sink_ext_subscription(struct userdata *);
void  pa_sink_ext_subscription_free(struct pa_sink_evsubscr *);
char *pa_sink_ext_get_name(struct pa_sink *);

#endif /* foosinkextfoo */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
