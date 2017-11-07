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
