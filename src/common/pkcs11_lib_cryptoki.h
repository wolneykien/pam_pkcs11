/*
 * PKCS #11 library Cryptoki lowlevel API.
 * Copyright (C) 2017 Paul Wolneykien <manowar@altlinux.org>,
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
#ifndef __PKCS11_LIB_CRYPTOKI_H__
#define __PKCS11_LIB_CRYPTOKI_H__

#include "pkcs11_lib.h"
#include "rsaref/pkcs11.h"

#ifndef __PKCS11_LIB_C__
#define PKCS11_EXTERN extern
#else
#define PKCS11_EXTERN
#endif

PKCS11_EXTERN CK_FUNCTION_LIST_PTR pkcs11_get_funcs (pkcs11_handle_t *h);
PKCS11_EXTERN CK_SESSION_HANDLE pkcs11_get_session (pkcs11_handle_t *h);

#undef PKCS11_EXTERN

/* end of pkcs11_lib_cryptoki.h */
#endif
