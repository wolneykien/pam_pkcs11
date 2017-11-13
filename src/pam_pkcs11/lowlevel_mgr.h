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
* This module manages dynamic load of lowlevel modules.
*/

#ifndef _LOWLEVEL_MGR_H_
#define _LOWLEVEL_MGR_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../scconf/scconf.h"
#include "../lowlevel/lowlevel_api.h"
#include "../common/pkcs11_lib.h"

/*
* lowlevel module descriptor
*/
struct lowlevel_instance {
    void *module_handler;
    const char *module_name;
    const char *module_path;
    pkcs11_handle_t *ph;
    void *module_data;
    lowlevel_funcs funcs;
};

/*
* Load and initialize a module.
* Returns descriptor on success, NULL on fail.
*/
struct lowlevel_instance *load_llmodule( scconf_context *ctx, const char * name,
                                         pkcs11_handle_t *ph );

/**
* Unload a module.
*/
void unload_llmodule( struct lowlevel_instance *module );

/**
* Load lowlevel module and return its handle.
*/
struct lowlevel_instance *load_lowlevel( scconf_context *ctx,
                                         pkcs11_handle_t *ph );

#endif
