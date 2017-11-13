/*
 * PAM-PKCS11 lowlevel modules
 * Copyright (C) 2017 Paul Wolneykien <manowar@altlinux.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * $Id$
 */

#ifndef __LOWLEVEL_H_
#define __LOWLEVEL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"

#include "lowlevel_api.h"


/**
* Structure to be filled on lowlevel module initialization
*/
typedef struct lowlevel_module_st {
    /** lowlevel name */
    const char *name; 
    /** lowlevel configuration block */
    scconf_block *block;
    /** debug level to set before call entry points */
    int  dbg_level; 
    /** pointer to lowlevel local data */
    void *context;
    /** PKCS#11 function list (relies on the lowlevel
    module implementation to include the proper version
    of pkcs11.h) */
    CK_FUNCTION_LIST_PTR p11;
    /** Used to set the current PKCS#11 session */
    void (*set_session) (void *context, CK_SESSION_HANDLE session);
    /** module de-initialization */
    void (*deinit)(void *context);
    lowlevel_funcs funcs;
} lowlevel_module;

#define _DEFAULT_LOWLEVEL_INIT_MODULE(module, name, blk)           \
	module = calloc(1, sizeof (lowlevel_module));                  \
	if (!module) return NULL;                                      \
	module->name    = name;                                        \
	module->block   = blk;                                         \
	module->dbg_level  = get_debug_level()

#define _DEFAULT_LOWLEVEL_INIT                                      \
lowlevel_module* lowlevel_module_init(lowlevel_module *module) {    \
    return module;                                                  \
}

/* end of lowlevel.h file */
#endif
