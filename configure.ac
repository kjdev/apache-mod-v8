#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(mod_v8, 0.0.1)

AC_CONFIG_SRCDIR([mod_v8.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE(mod_v8, 0.0. 1, [NO-DEFINE])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CXX
AC_PROG_LIBTOOL

# Option for v8 isolate
AC_ARG_ENABLE(v8-isolate,
  AC_HELP_STRING([--enable-v8-isolate],
    [enable v8 isolate [default=no]]),
  [ENABLED_V8_ISOLATE="${enableval:-yes}"],
  [ENABLED_V8_ISOLATE=no]
)
AS_IF([test "x${ENABLED_V8_ISOLATE}" = xyes],
    [AC_DEFINE([AP_USE_V8_ISOLATE], [1], [enable v8 isolate])]
)

# Checks for v8
AC_ARG_WITH(
  v8,
  [AC_HELP_STRING([--with-v8=PATH],
    [v8 include path [default=/usr/include]])],
  [V8_PATH="$withval"],
  [V8_PATH="/usr/include"]
)

AC_CHECK_FILE(
  "${V8_PATH}/v8.h",
  [V8_INCLUDEDIR=${V8_PATH}],
  [AC_MSG_ERROR([Missing required v8 header.])]
)

AC_ARG_WITH(
  v8-lib,
  [AC_HELP_STRING([--with-v8-lib=PATH],
    [v8 library path [default=no]])],
  [V8_LIBPATH="$withval"],
  [V8_LIBPATH="no"]
)

AS_IF([test "x${V8_LIBPATH}" != xno],
  V8_LDFLAGS="-L${V8_LIBPATH}"
)

AC_MSG_CHECKING([for v8 library])
AC_LANG(C++)
SAVED_LDFLAGS=$LDFLAGS
LDFLAGS="${LDFLAGS} ${V8_LDFLAGS} -lv8"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [#include "v8.h"],
    [v8::HandleScope dummy])],
  [V8_LIBS="-lv8"],
  [AC_MSG_ERROR([Missing required v8 library.])]
)
AC_MSG_RESULT(yes)
LDFLAGS=$SAVED_LDFLAGS

# v8 libraries.
V8_INCLUDES="-I${V8_INCLUDEDIR}"
V8_LDFLAGS="${V8_LDFLAGS} ${V8_LIBS}"
AC_SUBST(V8_INCLUDES)
AC_SUBST(V8_LDFLAGS)
AC_SUBST(V8_LIBS)


# Checks for apxs
AC_ARG_WITH(apxs,
  [AC_HELP_STRING([--with-apxs=PATH], [apxs path [default=yes]])],
  [APXS_PATH="$withval"],
  [APXS_PATH="/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"]
)

AC_PATH_PROG(APXS, apxs, no, ${APXS_PATH})

AS_IF([test "x${APXS}" = xno], AC_MSG_ERROR([apxs not found]),
  [test "x${APXS}" = x], AC_MSG_ERROR([apxs not found])
)

APXS_CFLAGS=`${APXS} -q CFLAGS 2> /dev/null`
APXS_CPPFLAGS=`${APXS} -q CPPFLAGS 2> /dev/null`
APXS_LDFLAGS=`${APXS} -q LDFLAGS 2> /dev/null`
APXS_LIBS=`${APXS} -q LIBS 2> /dev/null`
APXS_LIBEXECDIR=`${APXS} -q LIBEXECDIR 2> /dev/null`

APXS_INCLUDEDIR=`${APXS} -q INCLUDEDIR 2> /dev/null`
APXS_INCLUDES="-I${APXS_INCLUDEDIR}"

# Checks for apr
AC_ARG_WITH(apr,
  [AC_HELP_STRING([--with-apr=PATH], [apr config path [default=yes]])],
  [APR_CONFIG="$withval"],
  [with_apr=yes]
)

AC_MSG_CHECKING([whether apr])
AS_IF([test "x$with_apr" != xno],
  [
   if test ! -x "${APR_CONFIG}" -o -z "${APR_CONFIG}"; then
     APR_PATH=`${APXS} -q APR_BINDIR 2> /dev/null`
     APR_CONFIG="${APR_PATH}/apr-1-config"
     if test ! -x "${APR_CONFIG}"; then
       APR_CONFIG="${APR_PATH}/apr-config"
     fi
   fi
   APR_INCLUDES=`${APR_CONFIG} --includes 2> /dev/null`
   APR_CFLAGS=`${APR_CONFIG} --cflags 2> /dev/null`
   APR_CPPFLAGS=`${APR_CONFIG} --cppflags 2> /dev/null`
   APR_LDFLAGS=`${APR_CONFIG} --ldflags 2> /dev/null`
   APR_LIBS=`${APR_CONFIG} --libs 2> /dev/null`
   AC_MSG_RESULT(enable)
  ],
  AC_MSG_RESULT(disable)
)

# Checks for apu
AC_ARG_WITH(apu,
  [AC_HELP_STRING([--with-apu=PATH], [apu config path [default=no]])],
  [APU_CONFIG="$withval"],
  [with_apu=no]
)

AC_MSG_CHECKING([whether apu])
AS_IF([test "x$with_apu" != xno],
  [
   if test ! -x "${APU_CONFIG}" -o -z "${APU_CONFIG}"; then
     APU_PATH=`${APXS} -q APU_BINDIR 2> /dev/null`
     APU_CONFIG="${APU_PATH}/apu-1-config"
     if test ! -x "${APU_CONFIG}"; then
       APU_CONFIG="${APU_PATH}/apu-config"
     fi
   fi
   APU_INCLUDES=`${APU_CONFIG} --includes 2>/dev/null`
   APU_CFLAGS=`${APU_CONFIG} --cflags 2> /dev/null`
   APU_CPPFLAGS=`${APU_CONFIG} --cppflags 2> /dev/null`
   APU_LDFLAGS=`${APU_CONFIG} --ldflags 2> /dev/null`
   APU_LIBS=`${APU_CONFIG} --libs 2> /dev/null`
   AC_MSG_RESULT(enable)
  ],
  AC_MSG_RESULT(disable)
)

# Checks for apreq2.
AC_ARG_WITH(apreq2,
  [AC_HELP_STRING([--with-apreq2=PATH], [apreq2 config path [default=yes]])],
  [APREQ2_CONFIG="$withval"],
  [with_apreq2=yes]
)

AS_IF([test "x$with_apreq2" != xno],
  [
   if test ! -x "${APREQ2_CONFIG}" -o -z "${APREQ2_CONFIG}"; then
     SEARCH_PATH="/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
     AC_PATH_PROG(APREQ2_CONFIG, apreq2-config, no, ${SEARCH_PATH})
     AS_IF(
       [test "x${APREQ2_CONFIG}" = xno], AC_MSG_ERROR([apreq2-config not found]),
       [test "x${APREQ2_CONFIG}" = x], AC_MSG_ERROR([apreq2-config not found])
     )
   fi
   APREQ2_INCLUDES=`${APREQ2_CONFIG} --includes 2> /dev/null`
   APREQ2_LDFLAGS=`${APREQ2_CONFIG} --ldflags 2> /dev/null`
   APREQ2_LIBS=`${APREQ2_CONFIG} --libs 2> /dev/null`
  ],
  AC_MSG_ERROR(apreq2 not found)
)

# Apache libraries
APACHE_MODULEDIR="${APXS_LIBEXECDIR}"
APACHE_INCLUDES="${APXS_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES} ${APREQ2_INCLUDES}"
APACHE_CFLAGS="${APXS_CFLAGS} ${APR_CFLAGS} ${APU_CFLAGS}"
APACHE_CPPFLAGS="${APXS_CPPFLAGS} ${APR_CPPFLAGS} ${APU_CPPFLAGS}"
APACHE_LDFLAGS="${APXS_LDFLAGS} ${APR_LDFLAGS} ${APU_LDFLAGS} ${APREQ2_LDFLAGS}"
APACHE_LIBS="${APXS_LIBS} ${APR_LIBS} ${APU_LIBS} ${APREQ2_LIBS}"

AC_SUBST(APACHE_MODULEDIR)
AC_SUBST(APACHE_INCLUDES)
AC_SUBST(APACHE_CFLAGS)
AC_SUBST(APACHE_CPPFLAGS)
AC_SUBST(APACHE_LDFLAGS)
AC_SUBST(APACHE_LIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
