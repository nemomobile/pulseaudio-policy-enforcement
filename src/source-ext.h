#ifndef foosourceextfoo
#define foosourceextfoo

#include "userdata.h"

struct pa_source;

pa_subscription *pa_source_ext_subscription(struct userdata *);
char *pa_source_ext_get_name(struct pa_source *);

#endif /* foosourceextfoo */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
