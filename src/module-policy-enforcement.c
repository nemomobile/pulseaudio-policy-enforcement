#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <pulsecore/pulsecore-config.h>

#include <pulse/timeval.h>
#include <pulse/xmalloc.h>

#include <pulsecore/macro.h>
#include <pulsecore/module.h>
#include <pulsecore/idxset.h>
#include <pulsecore/client.h>
#include <pulsecore/core-util.h>
#include <pulsecore/core-error.h>
#include <pulsecore/modargs.h>
#include <pulsecore/log.h>

#include "module-policy-enforcement-symdef.h"
#include "userdata.h"
#include "config-file.h"
#include "policy-group.h"
#include "classify.h"
#include "client-ext.h"
#include "sink-ext.h"
#include "source-ext.h"
#include "sink-input-ext.h"
#include "source-output-ext.h"
#include "dbusif.h"

#ifndef PA_DEFAULT_CONFIG_DIR
#define PA_DEFAULT_CONFIG_DIR "/etc/pulse"
#endif

PA_MODULE_AUTHOR("Janos Kovacs");
PA_MODULE_DESCRIPTION("Policy enforcement module");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(TRUE);
PA_MODULE_USAGE(
    "config_file=<policy configuration file> "
    "dbus_if_name=<policy dbus interface> "
    "dbus_my_path=<our path> "
    "dbus_policyd_path=<policy daemon's path>"
    "dbus_policyd_name=<policy daemon's name>"
);

static const char* const valid_modargs[] = {
    "config_file",
    "dbus_if_name",
    "dbus_my_path",
    "dbus_policyd_path",
    "dbus_policyd_name",
    NULL
};


int pa__init(pa_module *m) {
    struct userdata *u = NULL;
    pa_modargs      *ma = NULL;
    const char      *cfgfile;
    const char      *ifnam;
    const char      *mypath;
    const char      *pdpath;
    const char      *pdnam;
    
    pa_assert(m);
    
    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("Failed to parse module arguments.");
        goto fail;
    }

    cfgfile = pa_modargs_get_value(ma, "config_file", NULL);
    ifnam   = pa_modargs_get_value(ma, "dbus_if_name", NULL);
    mypath  = pa_modargs_get_value(ma, "dbus_my_path", NULL);
    pdpath  = pa_modargs_get_value(ma, "dbus_policyd_path", NULL);
    pdnam   = pa_modargs_get_value(ma, "dbus_policyd_name", NULL);

    
    u = pa_xnew0(struct userdata, 1);
    u->core     = m->core;
    u->module   = m;
    u->scl      = pa_client_ext_subscription(u);
    u->ssnk     = pa_sink_ext_subscription(u);
    u->ssrc     = pa_source_ext_subscription(u);
    u->ssi      = pa_sink_input_ext_subscription(u);
    u->sso      = pa_source_output_ext_subscription(u);
    u->groups   = pa_policy_groupset_new(u);
    u->classify = pa_classify_new(u);
    u->dbusif   = pa_policy_dbusif_init(u, ifnam, mypath, pdpath, pdnam);

    pa_policy_groupset_update_default_sink(u, PA_IDXSET_INVALID);
    pa_policy_groupset_create_default_group(u);

    if (!pa_policy_parse_config_file(u, cfgfile))
        goto fail;
    
    m->userdata = u;
    
    if (u->scl == NULL || u->ssnk == NULL || u->ssi == NULL)
        goto fail;
       
    pa_modargs_free(ma);
    
    return 0;
    
 fail:
    
    if (ma)
        pa_modargs_free(ma);
    
    pa__done(m);
    
    return -1;
}

void pa__done(pa_module *m) {
    struct userdata *u;
    
    pa_assert(m);
    
    if (!(u = m->userdata))
        return;
    
    pa_policy_dbusif_done(u);

    pa_client_ext_subscription_free(u->scl);
    pa_sink_ext_subscription_free(u->ssnk);
    pa_source_ext_subscription_free(u->ssrc);
    pa_sink_input_ext_subscription_free(u->ssi);
    pa_source_output_ext_subscription_free(u->sso);
    
    pa_policy_groupset_free(u->groups);
    pa_classify_free(u->classify);
    
    pa_xfree(u);
}


/*
 * For the time being the prototype is in the userdata.h which is
 * not the best possible place for it
 */
const char *pa_policy_file_path(const char *file, char *buf, size_t len)
{
    snprintf(buf, len, "%s/x%s", PA_DEFAULT_CONFIG_DIR, file);

    return buf;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */


