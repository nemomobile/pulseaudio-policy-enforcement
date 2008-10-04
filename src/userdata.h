#ifndef foouserdatafoo
#define foouserdatafoo

#include <pulsecore/core.h>

#define PA_POLICY_DEFAULT_GROUP_NAME     "othermedia"

#define PA_PROP_APPLICATION_PROCESS_ARGS "application.process.args"
#define PA_PROP_POLICY_GROUP             "policy.group"
#define PA_PROP_POLICY_DEVTYPELIST       "policy.device.typelist"


struct pa_policy_groupset;
struct pa_classify;
struct pa_policy_dbusif;

struct userdata {
    pa_core                   *core;
    pa_module                 *module;
    pa_subscription           *scl;       /* client event susbscription */
    pa_subscription           *ssnk;      /* sink event subscription */
    pa_subscription           *ssi;       /* sink input event susbscription */
    struct pa_policy_groupset *groups;    /* policy groups */
    struct pa_classify        *classify;  /* rules for classification */
    struct pa_policy_dbusif   *dbusif;
};


/*
 * Some day this should go to a better place
 */
const char *pa_policy_file_path(const char *file, char *buf, size_t len);


#endif

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
