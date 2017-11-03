/*
 * PKCS #11 lowlevel module wrapper.
 * Copyright (C) 2017 Paul Wolneykien <manowar@altlinux.org>.
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
 * $Id$
 */

/*
* This module manages dynamic load of mapping modules.
*/

#define _LOWLEVEL_MGR_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <dlfcn.h>

#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../lowlevel/lowlevel.h"
#include "lowlevel_mgr.h"

/*
* Load and initialize a lowlevel module.
* Returns descriptor on success, NULL on fail.
*/
struct lowlevel_instance *load_llmodule(scconf_context *ctx, const char * name) {

	const scconf_block *root;
	scconf_block **blocks, *blk;
	struct lowlevel_instance *mymodule;
	lowlevel_module * (*lowlevel_init)(lowlevel_module *module);
	void *handler = NULL;
	const char *libname = NULL;
	lowlevel_module *res = NULL;

	/* get module info */
	root = scconf_find_block(ctx, NULL, "pam_pkcs11");
	if (!root) return NULL; /* no pam_pkcs11 { ...  } root block */
    
	blocks = scconf_find_blocks(ctx, root, "lowlevel", name);
	if (!blocks) return NULL; /* named lowlevel not found */    
	blk = blocks[0]; /* use the first one */
	free(blocks);
    
	if (!blk) {
	    DBG1("Lowlevel entry '%s' not found.", name);
	} else {
	    /* compose module path */
 	    libname = scconf_get_str(blk, "module", NULL);
	}

    DBG1("Loading dynamic module for lowlevel '%s'", name);
    handler = dlopen(libname, RTLD_NOW);
    
    if (!handler) {
		DBG3("dlopen failed for module: %s, path: %s. Error: %s",
             name, libname, dlerror());
		return NULL;
    }

    lowlevel_init = ( lowlevel_module * (*)(lowlevel_module *module) ) dlsym(handler, "lowlevel_module_init");
    
    if ( !lowlevel_init ) {
		dlclose(handler);
		DBG1("Module %s is not a lowlevel module", name);
		return NULL;
    }

    _DEFAULT_LOWLEVEL_INIT_MODULE(res, name, blk);

    res = lowlevel_init(res);
    if (!res ) { /* init failed */
		DBG1("Module %s init failed", name);
		dlclose(handler);
		return NULL;
    }

	/* allocate data */
	mymodule = malloc (sizeof(struct lowlevel_instance));
	if (!mymodule) {
		DBG1("No space to alloc module entry: '%s'", name);
		return NULL;
	}
    
	mymodule->module_handler = handler;
	mymodule->module_name = name;
	mymodule->module_path = libname;
	mymodule->module_data = res;

	return mymodule;
}

void unload_llmodule( struct lowlevel_instance *module ) {
	if (!module) return;

	if ( module->module_data && module->module_data->deinit ) {
        DBG1("Calling %s->deinit", module->module_name);
		(*module->module_data->deinit)(module->module_data->context);
	}

    free(module->module_data);
	module->module_data = NULL;

    if (module->module_handler) {
		DBG1("Unloading module %s", module->module_name);
		dlclose(module->module_handler);
        module->module_handler = NULL;
	}
    
	/* don't free name and libname: they are elements of
	scconf tree */
	free(module);
	return;
}

struct lowlevel_instance *load_lowlevel( scconf_context *ctx ) {
	const scconf_block *root = scconf_find_block(ctx, NULL, "pam_pkcs11");
	if (!root) {
		DBG("No pam_pkcs11 block in config file");
		return NULL;
	}
    
	const char *name = scconf_get_str(root, "use_lowlevel", NULL);
	if (!name) {
        DBG("No use_lowlevel entry found in config");
        return NULL;
	}
    
    struct lowlevel_instance *module = load_llmodule(ctx, name);
    if (module) {
        return module;
	}

    return NULL;
}
