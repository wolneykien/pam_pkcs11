/*#include <opensc/opensc.h>*/
#include "opensc.h"
#include "isbc/pkcs11.h"
#include <time.h>

#include "lowlevel.h"

struct context
{
    sc_context_t *ctx;
    CK_FUNCTION_LIST_PTR p11;
    CK_SESSION_HANDLE session;
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
        goto err;
	}
    
    return context;

 err:
    free (context);
    return NULL;
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
set_session (void *context, CK_SESSION_HANDLE session)
{
    if (!_context) return;
    struct context *context = (struct context *) _context;
    context->session = session;
}

#define EVENT_INITIAL          0x01
#define EVENT_INIT_TOKEN       0x02
#define EVENT_USER_PIN_CHANGED 0x03
#define EVENT_SO_PIN_CHANGED   0x04
#define EVENT_USER_PIN_ERROR   0x05
#define EVENT_SO_PIN_ERROR     0x06

#define EVENT_FLAG_UNKNOWN     0x40
#define EVENT_FLAG_MINIDRIVE   0x80

struct jorunal_record
{
    uint32_t timestamp;
    uint8_t  event_type;
    uint8_t  _reserved_;
};

static int
pin_needs_change (void *_context, unsigned int slot_num, int sopin)
{
    if (!_context) return -1;
    struct context *context = (struct context *) _context;

    if (!context->p11)
    {
        ERR ("Needs PKCS#11 handle. Please, set \"p11\" before module initialization");
        return -1;
    }
    if (!context->session)
    {
        ERR ("Needs PKCS#11 session. Please, use set_session() to set it");
        return -1;
    }

    CK_ULONG len = 0L;
	if (p11->C_ISBC_ScribbleRead (context->session, 0, NULL, &len) != CKR_OK) {
		ERR ("Journal reading error");
        return -1;
	}

	if (0 == len)
	{
		DBG ("Journal is empty");
        return PIN_NOT_INITIALIZED;
	}

    jorunal_record *recs = calloc (len / sizeof (jorunal_record), sizeof (jorunal_record));
    if (!recs)
    {
        ERR ("Unable to allocate memory for the journal!");
        return -1;
    }
    
	if (p11->C_ISBC_ScribbleRead (context->session, 0, recs, &len) != CKR_OK)
	{
		ERR ("Journal reading error (2)");
        return -1;
	}

    int initizlized = 0;
    time_t user_last_changed = (time_t) 0;
    time_t so_last_changed = (time_t) 0;
    
    jorunal_record *rec = recs;
	while (rec < (recs + len / sizeof (jorunal_record)))
	{
        switch (rec->event_type)
        {
        case EVENT_INITIAL:
        case EVENT_INIT_TOKEN:
            initizlized = 1;
            break;
        case EVENT_USER_PIN_CHANGED:
        case EVENT_USER_PIN_CHANGED | EVENT_FLAG_MINIDRIVE:
            // FIXME: host byte order
            if ((time_t) rec->timestamp > user_last_changed)
                user_last_changed = (time_t) rec->timestamp;
            break;
        case EVENT_SO_PIN_CHANGED:
        case EVENT_SO_PIN_CHANGED | EVENT_FLAG_MINIDRIVE:
            // FIXME: host byte order
            if ((time_t) rec->timestamp > so_last_changed)
                so_last_changed = (time_t) rec->timestamp;
            break;
        }
        rec++;
	}

    free (recs);

    if (!initialized)
        return PIN_NOT_INITIALIZED;    

    if (sopin && so_last_changed == (time_t) 0)
        return PIN_DEFAULT;
    if (user_last_changed == (time_t) 0)
        return PIN_DEFAULT;
    
    time_t now = time ();
    
    if (sopin && (now - so_last_changed) > context->expiration_period)
        return PIN_EXPIRED;
    if (now - user_last_changed > context->expiration_period)
        return PIN_EXPIRED;
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
    module->context.p11 = module->p11;
    module->deinit = deinit;
    return module;
}
