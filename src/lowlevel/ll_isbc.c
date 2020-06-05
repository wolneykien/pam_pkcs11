#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*#include <opensc/opensc.h>*/
#include "opensc.h"
#include "isbc/cryptoki.h"
#include <time.h>
#include <arpa/inet.h>

#include "lowlevel.h"

struct context
{
    sc_context_t *ctx;
    CK_FUNCTION_LIST_PTR p11;
    CK_SESSION_HANDLE session;
    unsigned long expiration_period;
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
connect_card (struct context *context, unsigned int slot_num)
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
disconnect_card (struct connected *con)
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
    
    struct connected *con = connect_card (context, slot_num);
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
    
    disconnect_card (con);
    
    if (r != SC_SUCCESS) return -1;
    return count;
}

static void
set_session (void *_context, CK_SESSION_HANDLE session)
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

#define ESMART_TIME_BASE 1451606400 /* Jan 01 03:00:00 UTC 2016 */
                         

#pragma pack(push, 1)
struct journal_record
{
    uint32_t timestamp;
    uint8_t  event_type;
    uint8_t  _reserved_;
};
#pragma pack(pop)

static void
read_time (struct journal_record *rec)
{
    rec->timestamp = ntohl (rec->timestamp);
}

static int
pin_status (void *_context, unsigned int slot_num, int sopin)
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

    /*
      {cryptokiVersion = {major = 2 '\002', minor = 40 '('}, 
      manufacturerID = "ISBC", ' ' <repeats 28 times>, flags = 0, 
      libraryDescription = ' ' <repeats 32 times>, libraryVersion = {
      major = 1 '\001', minor = 0 '\000'}}
    */
    
    CK_INFO pInfo;
    if (context->p11->C_GetInfo (&pInfo) != CKR_OK) {
		ERR ("Unable to get information about the PKCS#11 library");
        return -1;
	}

    DBG5 ("Using version %d.%d implementing Cryptoki %d.%d by %32s",
          pInfo.libraryVersion.major, pInfo.libraryVersion.minor,
          pInfo.cryptokiVersion.major, pInfo.cryptokiVersion.minor,
          pInfo.manufacturerID);

    CK_ULONG len = 0L;
	if (context->p11->C_ISBC_ScribbleRead (context->session, 0, NULL, &len) != CKR_OK) {
		ERR ("Journal reading error");
        return -1;
	}

	if (0 == len)
	{
		DBG ("Journal is empty");
        return PIN_NOT_INITIALIZED;
	}

    struct journal_record *recs = malloc (len);
    if (!recs)
    {
        ERR ("Unable to allocate memory for the journal!");
        return -1;
    }
    
	if (context->p11->C_ISBC_ScribbleRead (context->session, 0,
                                           (CK_BYTE_PTR) recs, &len) != CKR_OK)
	{
		ERR ("Journal reading error (2)");
        return -1;
	}

    int initialized = 0;
    uint32_t user_last_changed = 0;
    uint32_t so_last_changed = 0;
    
    struct journal_record *rec = recs;
    while ((!user_last_changed ||
           !so_last_changed) &&
           rec < (recs + len / sizeof (struct journal_record)))
	{
        read_time (rec);
        switch (rec->event_type)
        {
        case EVENT_INITIAL:
        case EVENT_INIT_TOKEN:
            initialized = 1;
            break;
        case EVENT_USER_PIN_CHANGED:
        case EVENT_USER_PIN_CHANGED | EVENT_FLAG_MINIDRIVE:
            if (!user_last_changed)
                user_last_changed = rec->timestamp;
            break;
        case EVENT_SO_PIN_CHANGED:
        case EVENT_SO_PIN_CHANGED | EVENT_FLAG_MINIDRIVE:
            if (!so_last_changed)
                so_last_changed = rec->timestamp;
            break;
        }
        rec++;
	}

    free (recs);

    DBG1 ("Initialized: %d", initialized);

    if (!initialized)
        return PIN_NOT_INITIALIZED;
    
    if (sopin)
    {
        if (so_last_changed == (time_t) 0)
            return PIN_DEFAULT;
    }
    else
        if (user_last_changed == (time_t) 0)
            return PIN_DEFAULT;

    if (0 != so_last_changed) {
	    so_last_changed = so_last_changed + ESMART_TIME_BASE;
	    DBG1 ("SO PIN last changed: %lu", so_last_changed);
    }
    if (0 != user_last_changed) {
	    user_last_changed = user_last_changed + ESMART_TIME_BASE;
	    DBG1 ("User PIN last changed: %lu", user_last_changed);
    }
 
    time_t now = time (NULL);
    struct tm tm;

    gmtime_r (&now, &tm);
    tm.tm_sec = 0; tm.tm_min = 0; tm.tm_hour = 0;
    now = mktime (&tm);

    DBG2 ("Current time: %lu, period: %lu", now, context->expiration_period);

    time_t last_changed;
    if (sopin)
        last_changed = so_last_changed;
    else
        last_changed = user_last_changed;
    
    gmtime_r (&last_changed, &tm);
    tm.tm_sec = 0; tm.tm_min = 0; tm.tm_hour = 0;
    last_changed = mktime (&tm);
    
    if (last_changed > now ||
        (now - last_changed) > context->expiration_period)
      return PIN_EXPIRED;

    return PIN_OK;
}

static void
deinit (void *_context)
{
    if (!_context) return;
    struct context *context = (struct context *) _context;
    close_context (context);
}

lowlevel_module* lowlevel_module_init (lowlevel_module *module) {
    set_debug_level (module->dbg_level);
    
    struct context *context = open_context ();
    context->p11 = module->p11;
    context->expiration_period = (unsigned long) (scconf_get_int (module->block, "pin_expire_min", 14 * 24 * 60) * 60); // 2 weeks by default
    
    module->funcs.pin_count = pin_count;
    module->funcs.pin_status = pin_status;

    module->set_session = set_session;
    module->context = context;
    module->deinit = deinit;
    
    return module;
}
