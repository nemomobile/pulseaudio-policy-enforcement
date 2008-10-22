#ifndef foosourceextfoo
#define foosourceextfoo

#include "userdata.h"

struct pa_source;

pa_subscription *pa_source_ext_subscription(struct userdata *);
char            *pa_source_ext_get_name(struct pa_source *);
int              pa_source_ext_set_mute(struct userdata *, char *, int);

#endif /* foosourceextfoo */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
