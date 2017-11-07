#include "lowlevel.h"
/*#include <opensc/opensc.h>*/
#include "opensc.h"

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

    sc_context_param_t params = {
        .app_name = "default",
        .flags = SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER,
    };
    
    int r = sc_context_create (&(context->ctx), &params);
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

static struct connected *
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

const uint8_t cmd0[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
const uint8_t cmd1[] = {0x00, 0xA4, 0x01, 0x00, 0x02, 0x8F, 0x01};

const uint8_t cmd_user0[] = {0x00, 0xA4, 0x01, 0x00, 0x02, 0x7F, 0x01};
const uint8_t cmd_user1[] = {0x00, 0x20, 0x00, 0x83};

const uint8_t cmd_so0[] = {0x00, 0x20, 0x00, 0x81};

static int
transmit (struct context *context, struct connected *con,
          const uint8_t *apdu_buf, size_t apdu_len,
          uint8_t *reply_buf, size_t reply_len, size_t *resp_len,
          uint16_t *status)
{
    sc_apdu_t apdu;
    
    int r = sc_bytes2apdu (context->ctx, apdu_buf, apdu_len, &apdu);
    if (r != SC_SUCCESS) return -1;

    apdu.resp = reply_buf;
	apdu.resplen = reply_len;

    *resp_len = 0;
    *status = 0;
    
    r = sc_transmit_apdu (con->card, &apdu);
    if (r != SC_SUCCESS) return -1;

    *resp_len = apdu.resplen;
    *status = (uint16_t) (((apdu.sw1 & 0xFF) << 8) | (apdu.sw2 & 0xFF));
    
    return 0;
}

static int
pin_count (void *_context, unsigned int slot_num, int sopin)
{
    uint8_t buf[0xffff];
    uint16_t status;
    size_t resp_len;
    
    if (!_context) return -1;
    struct context *context = (struct context *) _context;
    
    struct connected *con = connect (context, slot_num);
    if (!con) return -1;

    DBG ("Reset the card");
    
    int r = sc_reset (con->card, 0);

    DBG ("Sending APDUs...");
    
    if (r == SC_SUCCESS)
        r = transmit (context, con, cmd0, sizeof (cmd0), buf, sizeof (buf),
                      &resp_len, &status);
    if (r == SC_SUCCESS && status == 0x9000)
        r = transmit (context, con, cmd1, sizeof (cmd1), buf, sizeof (buf),
                      &resp_len, &status);

    if (r == SC_SUCCESS && status == 0x9000)
    {
        if (!sopin)
        {
            r = transmit (context, con, cmd_user0, sizeof (cmd_user0),
                          buf, sizeof (buf), &resp_len, &status);
            if (r == SC_SUCCESS && status == 0x9000)
                r = transmit (context, con, cmd_user1, sizeof (cmd_user1),
                              buf, sizeof (buf), &resp_len, &status);
        }
        else
            r = transmit (context, con, cmd_so0, sizeof (cmd_so0),
                          buf, sizeof (buf), &resp_len, &status);
    }

    int count = -1;

    if (r == SC_SUCCESS)
    {
        if ((status & 0xFFC0) == 0x63C0)
            count = status & 0x000F;
        else if (status == 0x6983)
            count = 0;
    }
    
    disconnect (con);
    
    if (r != SC_SUCCESS) return -1;
    return count;
}

static void
deinit (void *_context)
{
    if (!_context) return;
    struct context *context = (struct context *) _context;
    close_context (context);
}

lowlevel_module* lowlevel_module_init (lowlevel_module *module) {
    module->pin_count = pin_count;
    module->context = open_context ();
    module->deinit = deinit;
    return module;
}
