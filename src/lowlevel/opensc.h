/*
 * opensc.h: OpenSC library header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *               2005        The OpenSC project
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdint.h>
#include "types.h"

#define SC_SUCCESS 0
#define SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER 0x00000008

typedef struct sc_context  sc_context_t;
typedef struct sc_reader sc_reader_t;
typedef struct sc_card sc_card_t;

struct sc_card;
struct sc_apdu;

typedef struct sc_apdu sc_apdu_t;

typedef struct sc_thread_context sc_thread_context_t;

typedef struct {
	/** version number of this structure (0 for this version) */
	unsigned int  ver;
	/** name of the application (used for finding application
	 *  dependend configuration data). If NULL the name "default"
	 *  will be used. */
	const char    *app_name;
	/** context flags */
	unsigned long flags;
	/** mutex functions to use (optional) */
	sc_thread_context_t *thread_ctx;
} sc_context_param_t;

int sc_context_create(sc_context_t **ctx, const sc_context_param_t *parm);
int sc_release_context(sc_context_t *ctx);

int sc_connect_card(sc_reader_t *reader, struct sc_card **card);
int sc_disconnect_card(struct sc_card *card);

sc_reader_t *sc_ctx_get_reader(sc_context_t *ctx, unsigned int i);

int sc_bytes2apdu(sc_context_t *ctx, const uint8_t *buf, size_t len, sc_apdu_t *apdu);
int sc_transmit_apdu(struct sc_card *, struct sc_apdu *);

int sc_reset(struct sc_card *card, int do_cold_reset);

const char *sc_strerror(int sc_errno);
