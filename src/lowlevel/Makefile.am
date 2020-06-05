# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

if HAVE_OPENSC
pkglib_LTLIBRARIES = ll_isbc.la
ll_isbc_la_LDFLAGS = -module -avoid-version -shared
ll_isbc_la_LIBADD  = ../common/libcommon.la -lopensc
ll_isbc_la_SOURCES = ll_isbc.c
endif
