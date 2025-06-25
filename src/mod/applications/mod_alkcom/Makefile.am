include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_alkcom

mod_LTLIBRARIES = mod_alkcom.la
mod_alkcom_la_SOURCES  = mod_alkcom.c
mod_alkcom_la_CFLAGS   = $(AM_CFLAGS)
mod_alkcom_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_alkcom_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
