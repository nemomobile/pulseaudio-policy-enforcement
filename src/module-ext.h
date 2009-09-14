#ifndef foomoduleextfoo
#define foomoduleextfoo

#include "userdata.h"

struct pa_module;
struct pa_subscription;

struct pa_module_evsubscr {
    struct pa_subscription  *ev;
};


struct pa_module_evsubscr *pa_module_ext_subscription(struct userdata *);
void pa_module_ext_subscription_free(struct pa_module_evsubscr *);
void pa_module_ext_discover(struct userdata *);
char *pa_module_ext_get_name(struct pa_module *);


#endif /* foomoduleextfoo */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
