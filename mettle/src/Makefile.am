AM_CPPFLAGS = -I$(top_srcdir)/include/compat

lib_LTLIBRARIES = libmettle.la

libmettle_la_LIBADD = -ldnet
libmettle_la_LIBADD += -lcurl
libmettle_la_LIBADD += -leio
libmettle_la_LIBADD += -lev
libmettle_la_LIBADD += -lmbedtls
libmettle_la_LIBADD += -lmbedcrypto
libmettle_la_LIBADD += -lpthread
libmettle_la_LIBADD += -lsigar
libmettle_la_LIBADD += -lz

libmettle_la_SOURCES = mettle.c
libmettle_la_SOURCES += argv_split.c
libmettle_la_SOURCES += base64.c
libmettle_la_SOURCES += bufferev.c
libmettle_la_SOURCES += buffer_queue.c
libmettle_la_SOURCES += c2.c
libmettle_la_SOURCES += c2_http.c
libmettle_la_SOURCES += c2_tcp.c
libmettle_la_SOURCES += channel.c
libmettle_la_SOURCES += coreapi.c
libmettle_la_SOURCES += http_client.c
libmettle_la_SOURCES += log.c
libmettle_la_SOURCES += network_client.c
libmettle_la_SOURCES += network_server.c
libmettle_la_SOURCES += tlv.c
libmettle_la_SOURCES += stdapi/stdapi.c
libmettle_la_SOURCES += stdapi/webcam/webcam.c
if HOST_WIN
libmettle_la_SOURCES += inet_ntop.c inet_pton.c
libmettle_la_SOURCES += posix_win.c
libmettle_la_SOURCES += process_win.c
else
libmettle_la_SOURCES += process.c
endif
libmettle_la_SOURCES += util.c
if HOST_APPLE
libmettle_la_SOURCES += stdapi/webcam/apple_webcam.m
endif
if HOST_OSX
libmettle_la_SOURCES += stdapi/ui/osx_desktop.m
libmettle_la_SOURCES += stdapi/clipboard/osx_clipboard.m
endif
if HOST_LINUX
libmettle_la_SOURCES += stdapi/webcam/linux_webcam.c
endif

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
