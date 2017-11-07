/*
 * types.h: OpenSC general types
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

typedef struct sc_apdu {
	int cse;			/* APDU case */
	unsigned char cla, ins, p1, p2;	/* CLA, INS, P1 and P2 bytes */
	size_t lc, le;			/* Lc and Le bytes */
	const unsigned char *data;	/* S-APDU data */
	size_t datalen;			/* length of data in S-APDU */
	unsigned char *resp;		/* R-APDU data buffer */
	size_t resplen;			/* in: size of R-APDU buffer,
					 * out: length of data returned in R-APDU */
	unsigned char control;		/* Set if APDU should go to the reader */
	unsigned allocation_flags;	/* APDU allocation flags */

	unsigned int sw1, sw2;		/* Status words returned in R-APDU */
	unsigned char mac[8];
	size_t mac_len;

	unsigned long flags;

	struct sc_apdu *next;
} sc_apdu_t;
