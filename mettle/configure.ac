AC_INIT([mettle], m4_esyscmd([tr -d '\n' < VERSION]))

AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE([enable])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_OBJC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
LT_INIT

case $host_os in
	*darwin*)
		HOST_OS=apple
		OBJCFLAGS="$OBJCFLAGS -fobjc-arc"
		AC_DEFINE(HAVE_WEBCAM)
		AC_SUBST([PLATFORM_LDADD], ['-framework CoreMedia -framework CoreImage -framework AVFoundation -framework ImageIO'])
		AC_EGREP_CPP(yes,
			[#import <TargetConditionals.h>
			 #if TARGET_OS_OSX
			 yes
			 #endif],
			[HOST_OS=osx
			 AC_DEFINE(HAVE_DESKTOP_SCREENSHOT)
			 AC_DEFINE(HAVE_CLIPBOARD)
			 AC_SUBST([PLATFORM_LDADD], ["$PLATFORM_LDADD -framework Cocoa"])],
			[HOST_OS=ios])
		;;
	*linux*)
		HOST_OS=linux
		CPPFLAGS="$CPPFLAGS -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE"
		AC_DEFINE(HAVE_WEBCAM)
		;;
	*mingw*)
		HOST_OS=win
		CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE -D_POSIX -D_POSIX_SOURCE -D__USE_MINGW_ANSI_STDIO"
		CPPFLAGS="$CPPFLAGS -D_REENTRANT -D_POSIX_THREAD_SAFE_FUNCTIONS"
		CPPFLAGS="$CPPFLAGS -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0501"
		CFLAGS="$CFLAGS -static-libgcc"
		LDFLAGS="$LDFLAGS -static-libgcc"
		AC_SUBST([PLATFORM_LDADD], ['-lws2_32 -lwinpthread -static --static'])
		;;
esac

AM_CONDITIONAL([HOST_IOS],     [test x$HOST_OS = xios])
AM_CONDITIONAL([HOST_OSX],     [test x$HOST_OS = xosx])
AM_CONDITIONAL([HOST_APPLE],   [test x$HOST_OS = xios -o x$HOST_OS = xosx])
AM_CONDITIONAL([HOST_LINUX],   [test x$HOST_OS = xlinux])
AM_CONDITIONAL([HOST_WIN],     [test x$HOST_OS = xwin])

CHECK_LIBC_COMPAT

CFLAGS="$CFLAGS -Wall -Werror -std=gnu99 -fno-strict-aliasing -Wno-unused-variable -Wno-unused-function"

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_ARG_ENABLE([staticpie],
	AS_HELP_STRING([--enable-staticpie], [Building Static PIE]))
AS_IF([test "x$enable_staticpie" = "xyes"], [
	AC_SUBST([PLATFORM_LDADD], ['-static --static -pie'])
])

AC_OUTPUT
