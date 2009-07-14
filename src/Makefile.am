modlibexec_LTLIBRARIES = module-policy-enforcement.la

module_policy_enforcement_la_SOURCES = \
			module-policy-enforcement.c \
			config-file.c \
			client-ext.c \
			sink-ext.c \
			source-ext.c \
			sink-input-ext.c \
			card-ext.c \
			source-output-ext.c \
			classify.c \
			policy-group.c \
			context.c \
			dbusif.c
module_policy_enforcement_la_LDFLAGS = -module -avoid-version
module_policy_enforcement_la_LIBADD = $(AM_LIBADD) $(DBUS_LIBS) $(LIBPULSECORE_LIBS) $(LIBPULSE_LIBS)
module_policy_enforcement_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) $(LIBPULSE_CFLAGS) $(LIBPULSECORE_CFLAGS)
