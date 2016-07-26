AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libmettle.la

libmettle_la_LIBADD = -ldnet
libmettle_la_LIBADD += -leio
libmettle_la_LIBADD += -lev
libmettle_la_LIBADD += -lmbedcrypto
libmettle_la_LIBADD += -lmbedtls
libmettle_la_LIBADD += -lpthread
libmettle_la_LIBADD += -lsigar

libmettle_la_SOURCES = mettle.c
libmettle_la_SOURCES += base64.c
libmettle_la_SOURCES += buffer_queue.c
libmettle_la_SOURCES += channel.c
libmettle_la_SOURCES += log.c
libmettle_la_SOURCES += network_client.c
libmettle_la_SOURCES += tlv.c
libmettle_la_SOURCES += tlv_coreapi.c
libmettle_la_SOURCES += stdapi/stdapi.c
libmettle_la_SOURCES += util.c

if !HAVE_REALLOCARRAY
libmettle_la_SOURCES += compat/reallocarray.c
endif

if !HAVE_STRTONUM
libmettle_la_SOURCES += compat/strtonum.c
endif

if !HAVE_STRLCAT
libmettle_la_SOURCES += compat/strlcat.c
endif

if !HAVE_STRLCPY
libmettle_la_SOURCES += compat/strlcpy.c
endif

bin_PROGRAMS = mettle

mettle_SOURCES = main.c
mettle_LDADD = libmettle.la

mettle_LDFLAGS = $(PLATFORM_LDADD)
