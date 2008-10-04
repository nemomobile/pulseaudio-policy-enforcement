#ifndef foosinkextfoo
#define foosinkextfoo

#include "userdata.h"

struct pa_sink;

pa_subscription *pa_sink_ext_subscription(struct userdata *);
char *pa_sink_ext_get_name(struct pa_sink *);

#endif /* foosinkextfoo */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
