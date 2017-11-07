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

int sc_establish_context(sc_context_t **ctx, const char *app_name);
int sc_release_context(sc_context_t *ctx);

int sc_connect_card(sc_reader_t *reader, struct sc_card **card);
int sc_disconnect_card(struct sc_card *card);

sc_reader_t *sc_ctx_get_reader(sc_context_t *ctx, unsigned int i);

int sc_bytes2apdu(sc_context_t *ctx, const uint8_t *buf, size_t len, sc_apdu_t *apdu);
int sc_transmit_apdu(struct sc_card *, struct sc_apdu *);

int sc_reset(struct sc_card *card, int do_cold_reset);

const char *sc_strerror(int sc_errno);
