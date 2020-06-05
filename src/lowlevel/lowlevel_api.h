/*
 * PAM-PKCS11 lowlevel module API
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

#ifndef __LOWLEVEL_API_H_
#define __LOWLEVEL_API_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/**
 * PIN is OK (see pin_status()).
 */
#define PIN_OK 0

/**
 * PIN is not initialized (see pin_status()).
 */
#define PIN_NOT_INITIALIZED 1

/**
 * PIN never was used (see pin_status()).
 */
#define PIN_NEVER_USED 2

/**
 * PIN never was used (see pin_status()).
 */
#define PIN_DEFAULT 3

/**
 * PIN expired (see pin_status()).
 */
#define PIN_EXPIRED 4


/**
* Lowlevel functions
*/
typedef struct lowlevel_funcs_st {
    /** The context to call functions with */
    void *context;
    /** PIN-code input attempts */
    int (*pin_count) (void *context, unsigned int slot_num, int sopin);
    /** PIN-code status (needs to be changed, expired, etc.) */
    int (*pin_status) (void *context, unsigned int slot_num, int sopin);
} lowlevel_funcs;

/* end of lowlevel_api.h file */
#endif
