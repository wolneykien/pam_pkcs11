#include "lowlevel.h"
#include <libopensc/opensc.h>

struct context
{
    sc_context_t *ctx;
};

struct connected
{
	sc_card_t *card;
	sc_reader_t *reader;
};

static struct context *
open_context (void)
{
    struct context *context = calloc (1, sizeof (struct context));
    if (!context)
    {
        ERR ("Unable to allocate memory for ISBC low-level context");
        return NULL;
    }
    
    int r = sc_establish_context (&(context->ctx), "ll_isbc");
	if (r != SC_SUCCESS || !context->ctx)
    {
		ERR1 ("Failed to create OpenSC context: %s", sc_strerror (r));
        free (context);
		return NULL;
	}
    
    return context;
}

static void
close_context (struct context *context)
{
    sc_release_context (context->ctx);
    free (context);
}

static connected *
connect (struct context *context, unsigned int slot_num)
{
    struct connected *con = calloc (1, sizeof (struct connected));
    if (!con)
    {
        ERR ("Unable to allocate memory for ISBC connected context");
        return NULL;
    }
    
	con->reader = sc_ctx_get_reader(context->ctx, slot_num);
	if (!con->reader)
    {
		ERR1 ("Failed to access reader %u", slot_num);
        return NULL;
	}

    context->ctx->flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;
    
    int r = sc_connect_card (con->reader, &(con->card));
    if (r != SC_SUCCESS || !con->card)
    {
		ERR1 ("Could not connect to card: %s", sc_strerror (r));
        free (con);
        return NULL;
	}

    return con;
}

static void
disconnect (struct connected *con)
{
    if (!con) return;
    sc_disconnect_card (con->card);
    free (con);
}

const unsigned char cmd0[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
const unsigned char cmd1[] = {0x00, 0xA4, 0x01, 0x00, 0x02, 0x8F, 0x01};

const unsigned char cmd_user0[] = {0x00, 0xA4, 0x01, 0x00, 0x02, 0x7F, 0x01};
const unsigned char cmd_user1[] = {0x00, 0x20, 0x00, 0x83};

const unsigned char cmd_so0[] = {0x00, 0x20, 0x00, 0x81};

static int
transmit (static context *context, struct connected *con,
          unsigned char *apdu_buf, size_t apdu_len,
          u8 *reply_buf, size_t reply_len)
{
    sc_apdu_t apdu;
    
    int r = sc_bytes2apdu (context->ctx, apde_buf, apdu_len, &apdu);
    if (r != SC_SUCCESS) return -1;

    apdu.resp = reply_buf;
	apdu.resplen = reply_len;

    r = sc_transmit_apdu (con->card, &apdu);
    if (r != SC_SUCCESS) return -1;
    return 0;
}

static int
pin_count (void *_context, unsigned int slot_num, int sopin)
{
    u8 buf[0xffff];
    
    if (!_context) return -1;
    struct context *context = (struct context *) _context;
    
    struct connected *con = connect (context, slot_num);
    if (!con) return -1;

    DBG ("Reset the card");
    
    int r = sc_reset (con->card, 0);

    DBG ("Sending APDUs...");
    
    if (r == SC_SUCCESS)
        r = transmit (context, con, cmd0, sizeof (cmd0), buf, sizeof (buf));
    if (r == SC_SUCCESS)
        r = transmit (context, con, cmd0, sizeof (cmd1), buf, sizeof (buf));

    if (r == SC_SUCCESS)
    {
        if (!sopin)
        {
            r = transmit (context, con, cmd_user0, sizeof (cmd_user0),
                          buf, sizeof (buf));
            if (r == SC_SUCCESS)
                r = transmit (context, con, cmd_user1, sizeof (cmd_user1),
                              buf, sizeof (buf));
        }
        else
            r = transmit (context, con, cmd_so0, sizeof (cmd_so0),
                          buf, sizeof (buf));
    }

    int count = -1;

    if (r == SC_SUCCESS)
    {
        DBG4 ("APDU response: %02X %02X %02X %02X",
              buf[0], buf[1], buf[2], buf[3]);
    
        if (buf[0] == 0x80 && buf[1] == 0x20)
            if (buf[2] == 0x63 && buf[3] >= 0xC0 && buf[3] <= 0xCF)
                count = buf[3] & 0x0F;
            else if (buf[2] == 0x69 && buf[3] == 0x83)
                count = 0;
    }
    
    disconnect (con);
    
    if (r != SC_SUCCESS) return -1;
    return count;
}

static void
deinit (void *_context)
{
    if (!_context) return -1;
    struct context *context = (struct context *) _context;
    close_context (context);
}

lowlevel_module* lowlevel_module_init (lowlevel_module *module) {
    module->pin_count = pin_count;
    module->context = open_context ();
    module->deinit = deinit;
    return module;
}
