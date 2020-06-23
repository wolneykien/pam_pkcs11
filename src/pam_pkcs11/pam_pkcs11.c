/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
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

/* We have to make this definitions before we include the pam header files! */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif
/* OpenPAM used on *BSD and OS X */
#ifdef OPENPAM
#include <security/openpam.h>
#endif
#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/pkcs11_lib.h"
#include "../common/cert_vfy.h"
#include "../common/cert_info.h"
#include "../common/cert_st.h"
#include "pam_config.h"
#include "mapper_mgr.h"
#include "lowlevel_mgr.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(string) gettext(string)
#else
#define _(string) string
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif
#define LOGNAME   "PAM-PKCS11"  /* name for log-file entries */

#ifdef ENABLE_PWQUALITY
#include <pwquality.h>
#endif

/*
* comodity function that returns 1 on null, empty o spaced string
*/
static int is_spaced_str(const char *str) {
	char *pt=(char *)str;
	if(!str) return 1;
	if (!strcmp(str,"")) return 1;
	for (;*pt;pt++) if (!isspace(*pt)) return 0;
	return 1;
}

#if !defined(HAVE_SECURITY_PAM_EXT_H) && !defined(OPENPAM)
/*
 * implement pam utilities for older versions of pam.
 */
static int pam_prompt(pam_handle_t *pamh, int style, char **response, char *fmt, ...)
{
  int rv;
  struct pam_conv *conv;
  struct pam_message msg;
  struct pam_response *resp;
  /* struct pam_message *(msgp[1]) = { &msg}; */
  struct pam_message *(msgp[1]);
  msgp[0] = &msg;
  va_list va;
  char text[256];

  if (!fmt) return PAM_SUCCESS;

  va_start(va, fmt);
  vsnprintf(text, sizeof text, fmt, va);
  va_end(va);

  msg.msg_style = style;
  msg.msg = text;
  rv = pam_get_item(pamh, PAM_CONV, &conv);
  if (rv != PAM_SUCCESS)
    return rv;
  if ((conv == NULL) || (conv->conv == NULL))
    return PAM_CRED_INSUFFICIENT;
  rv = conv->conv(1, msgp, &resp, conv->appdata_ptr);
  if (rv != PAM_SUCCESS)
    return rv;
  if ((resp == NULL) || (resp[0].resp == NULL))
    return !response ? PAM_SUCCESS : PAM_CRED_INSUFFICIENT;
  if (response) {
     *response = strdup(resp[0].resp);
  }
  /* overwrite memory and release it */
  cleanse(resp[0].resp, strlen(resp[0].resp));
  free(&resp[0]);
  return PAM_SUCCESS;
}
#endif

#if !defined(HAVE_SECURITY_PAM_EXT_H) || defined(OPENPAM)
static void
pam_vsyslog(pam_handle_t *pamh, int priority, const char *fmt, va_list args)
{
    vsyslog(priority, fmt, args);
}

static void
pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    pam_vsyslog(priority, fmt, ap);
    va_end(ap);
}

/*
 * With OpenPAM pam_prompt resp arg cannot be NULL, so this is just a wrapper.
 */
#undef pam_prompt
#define pam_prompt(x, y, z, fmt, ...) pam_pkcs11_prompt((x), (y), (z), (fmt), ##__VA_ARGS__)

static int pam_pkcs11_prompt(const pam_handle_t *pamh, int style, char **resp, const char *fmt, ...)
{
  char *response = NULL;
  va_list va;
  int ret = 0;

  if (!fmt) return PAM_SUCCESS;

  va_start(va, fmt);
  ret = pam_vprompt(pamh, style, &response, fmt, va);
  va_end(va);

  free(response);

  return ret;
}
#endif

static void
_pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list ap;
    const char *token_label = pam_getenv( pamh, "PAM_PKCS11_TOKEN_LABEL" );
    const char *token_serial = pam_getenv( pamh, "PAM_PKCS11_TOKEN_SERIAL" );

    char fmt2[512];
    if ( token_label || token_serial ) {
      snprintf( fmt2, sizeof(fmt2) - 1, "[%s#%s]: %s",
		token_label ? token_label : "",
		token_serial ? token_serial : "",
		fmt );
		fmt = fmt2;
    }

    va_start (ap, fmt);
    pam_vsyslog (pamh, priority, fmt, ap);
    va_end (ap);
}


/*
 * Gets the user password. Depending whether it was already asked, either
 * a prompt is shown or the old value is returned.
 */
static int pam_get_pwd(pam_handle_t *pamh, char **pwd, char *text, int oitem, int nitem)
{
  int rv;
  const char *old_pwd;
  struct pam_conv *conv;
  struct pam_message msg;
  struct pam_response *resp;
  /* struct pam_message *(msgp[1]) = { &msg}; */
  const struct pam_message *(msgp[1]);
  msgp[0] = &msg;

  /* use stored password if variable oitem is set */
  if ((oitem == PAM_AUTHTOK) || (oitem == PAM_OLDAUTHTOK)) {
    /* try to get stored item */
    rv = pam_get_item(pamh, oitem, &old_pwd);
    if (rv != PAM_SUCCESS)
      return rv;
    if (old_pwd != NULL) {
      *pwd = strdup(old_pwd);
      return PAM_SUCCESS;
    }
  }

  /* ask the user for the password if variable text is set */
  if (text != NULL) {
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = text;
    rv = pam_get_item(pamh, PAM_CONV, &conv);
    if (rv != PAM_SUCCESS)
      return rv;
    if ((conv == NULL) || (conv->conv == NULL))
      return PAM_CRED_INSUFFICIENT;
    rv = conv->conv(1, msgp, &resp, conv->appdata_ptr);
    if (rv != PAM_SUCCESS)
      return rv;
    if ((resp == NULL) || (resp[0].resp == NULL))
      return PAM_CRED_INSUFFICIENT;
    *pwd = strdup(resp[0].resp);
    /* overwrite memory and release it */
    cleanse(resp[0].resp, strlen(resp[0].resp));
    free(&resp[0]);
    /* save password if variable nitem is set */
    if ((nitem == PAM_AUTHTOK) || (nitem == PAM_OLDAUTHTOK)) {
      rv = pam_set_item(pamh, nitem, *pwd);
      if (rv != PAM_SUCCESS)
        return rv;
    }
    return PAM_SUCCESS;
  }
  return PAM_CRED_INSUFFICIENT;
}

static void _get_pwd_error( pam_handle_t *pamh,
                            struct configuration_st *configuration,
                            int rv )
{
    if (!configuration->quiet) {
        _pam_syslog(pamh, LOG_ERR,
                    "pam_get_pwd() failed: %s", pam_strerror(pamh, rv));
    }
    pam_prompt(pamh, PAM_ERROR_MSG , NULL,
               _(configuration->prompts.pin_read_err));
    sleep(configuration->err_display_time);
}

static int check_pwd( pam_handle_t *pamh,
                      struct configuration_st *configuration,
                      char *password )
{
#ifdef DEBUG_SHOW_PASSWORD
    DBG1("password = [%s]", password);
#endif

    /* check password length */
	int pwdlen = strlen(password);
	int ret = 0;

	if ( configuration->pin_len_max &&
		 (pwdlen > configuration->pin_len_max) )
	{
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR,
						"password is too long");
        }
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _(configuration->prompts.pin_too_long_err));
        ret = PAM_AUTH_ERR;
	} else if ( pwdlen < configuration->pin_len_min ) {
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR,
                       "password is too short");
        }
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _(configuration->prompts.pin_too_short_err));
        ret = PAM_AUTH_ERR;
	} else if ( !configuration->nullok && pwdlen == 0 ) {
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR,
                       "password length is zero but 'nullok' "  \
                       "isn't set.");
        }
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _(configuration->prompts.empty_pin_err));
        ret = PAM_AUTH_ERR;
    }

	if (ret) {
        sleep(configuration->err_display_time);
		cleanse(password, strlen(password));
	}

    return ret;
}

static int pkcs11_module_load_init( pam_handle_t *pamh,
                                    struct configuration_st *configuration,
                                    pkcs11_handle_t **ph )
{
    int rv;
    
    /* load pkcs #11 module */
    DBG("loading pkcs #11 module...");
    rv = load_pkcs11_module(configuration->pkcs11_modulepath, ph);
    
    if (rv != 0) {
        ERR2("load_pkcs11_module() failed loading %s: %s",
             configuration->pkcs11_modulepath, get_error());
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR,
                       "load_pkcs11_module() failed loading %s: %s",
                       configuration->pkcs11_modulepath, get_error());
        }
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _("Error 2302: PKCS#11 module failed loading"));
        sleep(configuration->err_display_time);
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* initialise pkcs #11 module */
    DBG("initializing pkcs #11 module...");
    rv = init_pkcs11_module( *ph, configuration->support_threads );

    if (rv != 0) {
        release_pkcs11_module( *ph );
        ERR1("init_pkcs11_module() failed: %s", get_error());
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR,
                       "init_pkcs11_module() failed: %s",
                       get_error());
        }
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _("Error 2304: PKCS#11 module could not be initialized"));
        sleep(configuration->err_display_time);
        return PAM_AUTHINFO_UNAVAIL;
    }

    return rv;
}

static int pkcs11_find_slot( pam_handle_t *pamh,
                             struct configuration_st *configuration,
                             const char *login_token_name,
                             pkcs11_handle_t *ph,
                             unsigned int *slot_num,
                             int wait)
{
    int rv = -1;
    
    if (configuration->slot_description != NULL) {
        if (!wait) {
            rv = find_slot_by_slotlabel_and_tokenlabel(
                     ph,
                     configuration->slot_description,
                     login_token_name,
                     slot_num
            );
        } else {
            rv = wait_for_token_by_slotlabel(
                     ph,
                     configuration->slot_description,
                     login_token_name,
                     slot_num
            );
        }
    } else if (configuration->slot_num != -1) {
        if (!wait) {
            rv = find_slot_by_number_and_label(ph, configuration->slot_num,
                                               login_token_name, slot_num);
        } else {
          rv = wait_for_token(ph, configuration->slot_num,
                              login_token_name, slot_num);
        }
    }

    return rv;
}

static int pkcs11_open_session( pam_handle_t *pamh,
                                struct configuration_st *configuration,
                                pkcs11_handle_t *ph,
                                unsigned int slot_num,
                                int rw )
{
    int rv;
    
    rv = open_pkcs11_session( ph, slot_num, rw );
    
    if (rv != 0) {
        ERR1("open_pkcs11_session() failed: %s", get_error());
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR, "open_pkcs11_session() failed: %s", get_error());
        }
        pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2312: open PKCS#11 session failed"));
        sleep(configuration->err_display_time);
    }

    return rv;
}

static int pkcs11_close_session( pam_handle_t *pamh,
                                 struct configuration_st *configuration,
                                 pkcs11_handle_t *ph )
{
    int rv;

    rv = close_pkcs11_session(ph);
    
    if (rv != 0) {
        ERR1("close_pkcs11_session() failed: %s", get_error());
		if (!configuration->quiet) {
			_pam_syslog(pamh, LOG_ERR, "close_pkcs11_module() failed: %s", get_error());
		}
        pam_prompt(pamh, PAM_ERROR_MSG , NULL, ("Error 2344: Closing PKCS#11 session failed"));
        sleep(configuration->err_display_time);
    }

    return rv;
}

static void report_pkcs11_lib_error(pam_handle_t *pamh,
                                    const char *func,
                                    struct configuration_st *configuration)
{
    ERR2("%s() failed: %s", func, get_error());
    if (!configuration->quiet) {
        _pam_syslog(pamh, LOG_ERR, "%s() failed: %s", func, get_error());
    }
}

static int
check_warn_pin_count( pam_handle_t *pamh, pkcs11_handle_t *ph,
                      struct lowlevel_instance *lowlevel,
                      struct configuration_st *configuration,
                      unsigned int slot_num )
{
    int final_try = 0;
    int rv;

    rv = get_slot_user_pin_final_try(ph);
    if (rv) {
        if (rv < 0) report_pkcs11_lib_error(pamh, "get_slot_user_pin_final_try", configuration);
        final_try = 1;
        pam_prompt(pamh, PAM_ERROR_MSG, NULL,
                   _(configuration->prompts.pin_final_try));
        sleep(configuration->err_display_time);
    } else {
        rv = get_slot_user_pin_count_low(ph);
        if (rv) {
            if (rv < 0) report_pkcs11_lib_error(pamh, "get_slot_user_pin_count_low", configuration);

            int pins_left = -1;
            if ( lowlevel && lowlevel->funcs.pin_count) {
                pins_left = (*lowlevel->funcs.pin_count)(lowlevel->funcs.context, slot_num, 0);
                if (pins_left > 0) {
                    if (pins_left < configuration->pin_count_low) {
                        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                                   pins_left > 1 ?
                                     _(configuration->prompts.pin_n_only):
                                     _(configuration->prompts.pin_1_only),
                                   pins_left);
                    } else {
                        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                                   pins_left > 1 ?
                                     _(configuration->prompts.pin_n_left):
                                     _(configuration->prompts.pin_1_left),
                                   pins_left);
                    }
                } else if (pins_left == 0) {
                    pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                               _(configuration->prompts.pin_locked));
                } else {
                    ERR1("pin_count() from %s failed", lowlevel->module_name);
                    if (!configuration->quiet) {
                        _pam_syslog(pamh, LOG_ERR, "pin_count() from %s failed",
                                   lowlevel->module_name);
                    }
                }
            }

            if (pins_left < 0) {
                pam_prompt(pamh, PAM_ERROR_MSG, NULL,
                           _(configuration->prompts.were_incorrect));
                sleep(configuration->err_display_time);
            }
        }
    }

    return final_try;
}

static int _pam_putenv( pam_handle_t *pamh,
                        struct configuration_st *configuration,
                        const char *name,
                        const char *value )
{
    char env_temp[256];
    int rv;

    snprintf( env_temp, sizeof(env_temp) - 1, "%s=%.*s",
              name,
              (int)((sizeof(env_temp) - 1) - strlen(name) + 1),
              value );
    rv = pam_putenv( pamh, env_temp );

    if (rv) {
        ERR2( "Could not put %s into the environment: %s",
              name, pam_strerror(pamh, rv) );
        if ( !configuration->quiet ) {
            _pam_syslog( pamh, LOG_ERR,
                        "Could not put %s into environment: %s",
                        name, pam_strerror(pamh, rv) );
        }
    }

    return rv;
}

static int pam_set_pin( pam_handle_t *pamh, pkcs11_handle_t *ph,
                        unsigned int slot_num,
                        struct configuration_st *configuration,
                        char *old_pass,
                        int init_pin );

static int pam_do_login( pam_handle_t *pamh, pkcs11_handle_t *ph,
                         struct configuration_st *configuration,
                         const char *pass, int init_pin, int final_try );

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int i, rv;
  const char *user = NULL;
  char *password = NULL;
  unsigned int slot_num = 0;
  int is_a_screen_saver = 0;
  struct configuration_st *configuration;
  int pkcs11_pam_fail = PAM_AUTHINFO_UNAVAIL;

  pkcs11_handle_t *ph;
  cert_object_t *chosen_cert = NULL;
  cert_object_t **cert_list;
  int ncert;
  unsigned char random_value[128];
  unsigned char *signature;
  unsigned long signature_length;
  /* enough space to hold an issuer DN */
  char **issuer, **serial;
  const char *login_token_name = NULL;
  const char *service;
  int pin_to_be_changed = 0;
  int final_try = 0;
  int pin_locked = 0;

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, "/usr/share/locale");
  textdomain(PACKAGE);
#endif

  /* first of all check whether debugging should be enabled */
  for (i = 0; i < argc; i++)
    if (strcmp("debug", argv[i]) == 0) {
      set_debug_level(1);
    }

  pam_get_item(pamh, PAM_SERVICE, &service);

  /* call configure routines */
  configuration = pk_configure( service, argc, argv );
  if (!configuration ) {
	ERR("Error setting configuration parameters");
	return PAM_AUTHINFO_UNAVAIL;
  }

  /* Either slot_description or slot_num, but not both, needs to be used */
  if ((configuration->slot_description != NULL && configuration->slot_num != -1) || (configuration->slot_description == NULL && configuration->slot_num == -1)) {
	ERR("Error setting configuration parameters");
	return PAM_AUTHINFO_UNAVAIL;
  }

  if (configuration->verbose) {
      pam_prompt(pamh, PAM_TEXT_INFO , NULL,
                 _(configuration->prompts.start_auth));
  }

  login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");

  /*
   * card_only means: restrict the authentication to token only if
   * the user has already authenticated by the token.
   *
   * wait_for_card means:
   *  1) nothing if card_only isn't set
   *  2) if logged in, block in pam conversation until the token used for login
   *     is inserted
   *  3) if not logged in, block until a token that could be used for logging in
   *     is inserted
   * right now, logged in means PKC11_LOGIN_TOKEN_NAME is set,
   * but we could something else later (like set some per-user state in
   * a pam session module keyed off uid)
   */
  if (configuration->card_only) {
	if (configuration->screen_savers) {
	    DBG("Is it a screen saver?");
	    for (i=0; configuration->screen_savers[i]; i++) {
		if (strcmp(configuration->screen_savers[i], service) == 0) {
		    is_a_screen_saver = 1;
		    break;
		}
	    }
	}
  }

  if (!configuration->card_only || !login_token_name) {
	  /* Allow to pass to the next module if the auth isn't
         restricted to card only. */
      pkcs11_pam_fail = PAM_IGNORE;
  } else {
	pkcs11_pam_fail = PAM_CRED_INSUFFICIENT;
  }

  /* fail if we are using a remote server
   * local login: DISPLAY=:0
   * XDMCP login: DISPLAY=host:0 */
  {
	  char *display = getenv("DISPLAY");

	  if (display)
	  {
		  if (strncmp(display, "localhost:", 10) != 0 && (display[0] != ':')
			  && (display[0] != '\0')) {
			  ERR1("Remote login (from %s) is not (yet) supported", display);
			  _pam_syslog(pamh, LOG_ERR,
				  "Remote login (from %s) is not (yet) supported", display);
			  return pkcs11_pam_fail;
		  }
	  }
  }

  /* init openssl */
  rv = crypto_init(&configuration->policy);
  if (rv != 0) {
    ERR("Failed to initialize crypto");
    if (!configuration->quiet)
      _pam_syslog(pamh,LOG_ERR, "Failed to initialize crypto");
    return pkcs11_pam_fail;
  }
  
  /* look to see if username is already set */
  pam_get_item(pamh, PAM_USER, &user);
  if (user && user[0]) {
      DBG1("explicit username = [%s]", user);
  } else if (configuration->default_username) {
      user = configuration->default_username;
      DBG1("implicit username = [%s]", user);
      /* Set the configured default username in PAM to
         prevent other modules form asking the user for
         input. */
      rv = pam_set_item(pamh, PAM_USER,(const void *)user);
      if (rv != PAM_SUCCESS) {
          ERR1("pam_set_item() failed %s", pam_strerror(pamh, rv));
          if (!configuration->quiet) {
              _pam_syslog(pamh, LOG_ERR,
                         "pam_set_item() failed %s", pam_strerror(pamh, rv));
          }
      }
  }

  /* if we are using a screen saver, and we didn't log in using the smart card
   * drop to the next pam module.  */
  if (is_a_screen_saver && !login_token_name) {
	  goto exit_ignore;
  }

  rv = pkcs11_module_load_init( pamh, configuration, &ph );
  if ( rv != 0 ) {
      return pkcs11_pam_fail;
  }

  rv = pkcs11_find_slot( pamh, configuration, login_token_name, ph,
                         &slot_num, 0 );

  if (rv != 0) {
    if (!configuration->card_only) {
        /* If the login isn't restricted to card-only, then proceed
           to the next auth. module quietly. */
        release_pkcs11_module(ph);
        goto exit_ignore;
    }

    ERR("no suitable token available");
    if (!configuration->quiet) {
        _pam_syslog(pamh, LOG_ERR, "no suitable token available");
    }

    if (configuration->wait_for_card) {
        if (login_token_name) {
            pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                       _(configuration->prompts.insert_named),
                       login_token_name);
        } else {
            pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                       _(configuration->prompts.insert));
        }

        rv = pkcs11_find_slot( pamh, configuration, login_token_name, ph,
                               &slot_num, 1 );
    }
  }

  if (rv != 0) {
      release_pkcs11_module(ph);
      /* Still no card */
      if (pkcs11_pam_fail != PAM_IGNORE) {
          pam_prompt(pamh, PAM_ERROR_MSG,
                     NULL, _(configuration->prompts.no_card_err));
          sleep(configuration->err_display_time);
      } else {
          pam_prompt(pamh, PAM_TEXT_INFO,
                     NULL, _(configuration->prompts.no_card));
          goto exit_ignore;
      }
      return pkcs11_pam_fail;
  }

  /* Initialize the environment for syslog */
  _pam_putenv( pamh, configuration, "PAM_PKCS11_TOKEN_LABEL",
               get_slot_tokenlabel(ph) );
  _pam_putenv( pamh, configuration, "PAM_PKCS11_TOKEN_SERIAL",
               get_slot_tokenserial(ph) );

  if (configuration->verbose) {
      pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                 _(configuration->prompts.found),
                 _(configuration->token_type));
  }

  /* open pkcs #11 session */
  rv = pkcs11_open_session( pamh, configuration, ph, slot_num, 0 );
  if (rv != 0) {
    release_pkcs11_module(ph);
    return pkcs11_pam_fail;
  }

  /* We split the code into two cases based on configuration->ask_pin:
     first comes the simplified case, then the complete default one.

     There is some common code there, but we repeat it intentionally
     because this way the implementation of the ask-pin-later feature (by raorn@)
     will be as simple as just moving the second default part. */
  if (!configuration->ask_pin) {

  rv = get_slot_login_required(ph);
  if (rv == -1) {
    ERR1("get_slot_login_required() failed: %s", get_error());
    if (!configuration->quiet) {
		_pam_syslog(pamh, LOG_ERR, "get_slot_login_required() failed: %s", get_error());
	}
    pam_prompt(pamh, PAM_ERROR_MSG , NULL, _(configuration->prompts.login_failed));
    sleep(configuration->err_display_time);
    goto auth_failed_nopw;
  } else if (rv) {
    if (!is_a_screen_saver)
        pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                   _(configuration->prompts.welcome), get_slot_tokenlabel(ph));
    DBG("pkcs11_login is affected by false ask_pin (before ensuring that the user is the real owner of the card); this might be insecure");
    /* call pkcs#11 login with empty password to ensure that the user is the real owner of the card
     * we need to do thise before get_certificate_list because some tokens
     * can not read their certificates until the token is authenticated */
    rv = pkcs11_login(ph, NULL);
    if (rv != 0) {
      ERR1("open_pkcs11_login() failed: %s", get_error());
		if (!configuration->quiet) {
			_pam_syslog(pamh, LOG_ERR, "open_pkcs11_login() failed: %s", get_error());
        }
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _(configuration->prompts.login_failed));
        sleep(configuration->err_display_time);
        goto auth_failed_wrongpw;
    }
  }

  } /* end if (!configuration->ask_pin) */

  cert_list = get_certificate_list(ph, &ncert);
  if (rv<0) {
    ERR1("get_certificate_list() failed: %s", get_error());
    if (!configuration->quiet) {
		_pam_syslog(pamh, LOG_ERR, "get_certificate_list() failed: %s", get_error());
	}
    pam_prompt(pamh, PAM_ERROR_MSG , NULL, _(configuration->prompts.no_cert));
    sleep(configuration->err_display_time);
    goto auth_failed_nopw;
  }

  /* load mapper modules */
  load_mappers(configuration->ctx);
  /* load lowlevel modules */
  struct lowlevel_instance *lowlevel = load_lowlevel( configuration->ctx, ph );

  /* find a valid and matching certificates */
  int cert_rv = 0;
  char *user_desc = NULL;
  for (i = 0; i < ncert; i++) {
    X509 *x509 = (X509 *)get_X509_certificate(cert_list[i]);
    if (!x509 ) continue; /* sanity check */
    DBG1("verifying the certificate #%d", i + 1);
	if (configuration->verbose) {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                   _(configuration->prompts.cert_verif),
                   i + 1);
	}

    if (configuration->policy.eku_sc_logon_policy) {
      if (!verify_eku_sc_logon(x509)) {
        DBG("Certificate does not contain EKU Smart Card Logon");
        continue; /* try next certificate */
      }
    }

    /* verify certificate (date, signature, CRL, ...) */
    rv = 0;
    cert_rv = verify_certificate(x509,&configuration->policy);
    if (cert_rv != 1) {
        ERR1("verify_certificate() failed: %s", get_error());
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR,
                       "verify_certificate() failed: %s", get_error());
		}
        continue; /* try next certificate */
    }

    /* CA and CRL verified, now check/find user */

    if ( !user || is_spaced_str(user) || (configuration->default_username && strcmp(user, configuration->default_username) == 0) ) {
      /*
	if provided user is null or empty extract and set user
	name from certificate
      */
	DBG("Empty login: try to deduce from certificate");
	user = find_user_desc(x509, &user_desc);
	if (!user) {
          ERR2("find_user() failed: %s on cert #%d", get_error(),i+1);
          if (!configuration->quiet)
            _pam_syslog(pamh, LOG_ERR,
                     "find_user() failed: %s on cert #%d",get_error(),i+1);
	  continue; /* try on next certificate */
	} else {
          DBG1("certificate is valid and matches user %s",user);
	  /* try to set up PAM user entry with evaluated value */
	  rv = pam_set_item(pamh, PAM_USER,(const void *)user);
	  if (rv != PAM_SUCCESS) {
	    ERR1("pam_set_item() failed %s", pam_strerror(pamh, rv));
        if (!configuration->quiet) {
			_pam_syslog(pamh, LOG_ERR,
                   "pam_set_item() failed %s", pam_strerror(pamh, rv));
		}
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2332: setting PAM userentry failed"));
		sleep(configuration->err_display_time);
	    goto auth_failed_nopw;
      }
      chosen_cert = cert_list[i];
      break; /* end loop, as find user success */
    }

    } else {
      /* User provided:
         check whether the certificate matches the user */
        rv = match_user_desc(x509, user, &user_desc);
        if (rv < 0) { /* match error; abort and return */
          ERR1("match_user() failed: %s", get_error());
			if (!configuration->quiet) {
				_pam_syslog(pamh, LOG_ERR, "match_user() failed: %s", get_error());
			}
            pam_prompt(pamh, PAM_ERROR_MSG , NULL, _(configuration->prompts.no_user_match));
            sleep(configuration->err_display_time);
            goto auth_failed_nopw;
        } else if (rv == 0) { /* match didn't success */
          DBG("certificate is valid but does not match the user");
	  continue; /* try next certificate */
        } else { /* match success */
          DBG("certificate is valid and matches the user");
          chosen_cert = cert_list[i];
          break;
      }
    } /* if is_spaced string */
  } /* for (i=0; i<ncerts; i++) */

  /* now myCert points to our found certificate or null if no user found */
  if (!chosen_cert) {
      ERR("no valid certificate which meets all requirements found");
      if (cert_rv < 0) {
          switch (cert_rv) {
          case -2: // X509_V_ERR_CERT_HAS_EXPIRED:
              pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                         _(configuration->prompts.cert_expired));
              break;
          case -3: // X509_V_ERR_CERT_NOT_YET_VALID:
              pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                         _(configuration->prompts.cert_not_yet));
              break;
          case -4: // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
              pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                         _(configuration->prompts.cert_inv_sig));
              break;
          default:
              pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                         _(configuration->prompts.cert_inv));
              break;
          }
          sleep(configuration->err_display_time);
      } else {
          if (!configuration->quiet) {
              _pam_syslog(pamh, LOG_ERR,
                          "no valid certificate which meets all requirements found");
          }
          pam_prompt(pamh, PAM_ERROR_MSG , NULL, _(configuration->prompts.no_cert_match));
          sleep(configuration->err_display_time);
      }
      goto auth_failed_nopw;
  }


  if (configuration->ask_pin)
  {

  pin_locked = 0;
  rv = get_slot_user_pin_locked(ph);
  if (rv) {
      if (rv < 0) report_pkcs11_lib_error(pamh, "get_slot_user_pin_locked", configuration);
      pin_locked = 1;
  }

  rv = get_slot_user_pin_to_be_changed(ph);
  if (rv) {
      if (rv < 0) {
          report_pkcs11_lib_error(pamh,
                                  "get_slot_user_pin_to_be_changed",
                                  configuration);
      } else {
          pin_to_be_changed = 1;
      }
  }

  rv = get_slot_login_required(ph);
  if (rv == -1) {
    ERR1("get_slot_login_required() failed: %s", get_error());
    if (!configuration->quiet) {
		_pam_syslog(pamh, LOG_ERR, "get_slot_login_required() failed: %s", get_error());
	}
    pam_prompt(pamh, PAM_ERROR_MSG , NULL, _(configuration->prompts.login_failed));
    sleep(configuration->err_display_time);
    goto auth_failed_nopw;
  } else if (rv) {
      if (!is_a_screen_saver) {
          if (user_desc && strlen(user_desc) > 0) {
              pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                         pin_locked ?
                         _(configuration->prompts.welcome_user_locked) :
                         _(configuration->prompts.welcome_user),
                         get_slot_tokenlabel(ph), user_desc);
          } else {
              pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                         pin_locked ?
                         _(configuration->prompts.welcome_locked) :
                         _(configuration->prompts.welcome),
                         get_slot_tokenlabel(ph));
          }
      }

      if (pin_locked) {
          pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                     _(configuration->prompts.pin_locked));
          sleep(configuration->err_display_time);
          goto auth_failed_nopw;
      }

      final_try = check_warn_pin_count( pamh, ph, lowlevel,
                                        configuration, slot_num );

    /* no CKF_PROTECTED_AUTHENTICATION_PATH */
	rv = get_slot_protected_authentication_path(ph);
	if ((-1 == rv) || (0 == rv))
	{
		char password_prompt[256];

		snprintf(password_prompt,  sizeof(password_prompt),
                 _(configuration->prompts.pin_prompt),
                 _(configuration->token_type));
		if (configuration->use_first_pass) {
			rv = pam_get_pwd(pamh, &password, NULL, PAM_AUTHTOK, 0);
		} else if (configuration->try_first_pass) {
			rv = pam_get_pwd(pamh, &password, password_prompt, PAM_AUTHTOK,
					PAM_AUTHTOK);
		} else {
			rv = pam_get_pwd(pamh, &password, password_prompt, 0, PAM_AUTHTOK);
		}
		if (rv != PAM_SUCCESS) {
            _get_pwd_error( pamh, configuration, rv );
            goto auth_failed_nopw;
		}

        rv = check_pwd( pamh, configuration, password );
        if ( rv != 0 ) {
			goto auth_failed_wrongpw;
		}
	}
	else
	{
		pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                   _(configuration->prompts.enter_pin_pinpad),
                   _(configuration->token_type));
		/* use pin pad */
		password = NULL;
	}

    /* call pkcs#11 login to ensure that the user is the real owner of the card
     * we need to do thise before get_certificate_list because some tokens
     * can not read their certificates until the token is authenticated */
    rv = pam_do_login( pamh, ph, configuration, password, 0, final_try );
    if (rv != 0) goto auth_failed_wrongpw;
  }

  } /* end if (configuration->ask_pin) */

  /* if signature check is enforced, generate random data, sign and verify */
  if (configuration->policy.signature_policy) {
      if (configuration->verbose) {
          pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                     _(configuration->prompts.checking_sig));
      }


#ifdef notdef
    rv = get_private_key(ph);
    if (rv != 0) {
      ERR1("get_private_key() failed: %s", get_error());
      if (!configuration->quiet)
        _pam_syslog(pamh, LOG_ERR,
                 "get_private_key() failed: %s", get_error());
      goto auth_failed_nopw;
    }
#endif

    /* read random value */
    rv = get_random_value(random_value, sizeof(random_value));
    if (rv != 0) {
      ERR1("get_random_value() failed: %s", get_error());
		if (!configuration->quiet){
			_pam_syslog(pamh, LOG_ERR, "get_random_value() failed: %s", get_error());
		}
        pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2338: Getting random value failed"));
        sleep(configuration->err_display_time);
        goto auth_failed_nopw;
    }

    /* sign random value */
    signature = NULL;
    rv = sign_value(ph, chosen_cert, random_value, sizeof(random_value),
		    &signature, &signature_length);
    if (rv != 0) {
      ERR1("sign_value() failed: %s", get_error());
		if (!configuration->quiet) {
			_pam_syslog(pamh, LOG_ERR, "sign_value() failed: %s", get_error());
		}
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _(configuration->prompts.sig_failed));
        sleep(configuration->err_display_time);
        goto auth_failed_nopw;
    }

    /* verify the signature */
    DBG("verifying signature...");
    rv = verify_signature((X509 *)get_X509_certificate(chosen_cert),
             random_value, sizeof(random_value), signature, signature_length);
    if (signature != NULL) {
      free(signature);
    }
    if (rv != 0) {
      ERR1("verify_signature() failed: %s", get_error());
		if (!configuration->quiet) {
			_pam_syslog(pamh, LOG_ERR, "verify_signature() failed: %s", get_error());
		}
      pam_prompt(pamh, PAM_ERROR_MSG , NULL, _(configuration->prompts.sig_verif_failed));
      sleep(configuration->err_display_time);
      goto auth_failed_wrongpw;
    }

  } else {
      DBG("Skipping signature check");
  }

  /*
   * fill in the environment variables.
   */
  _pam_putenv( pamh, configuration, "PKCS11_LOGIN_TOKEN_NAME",
			   get_slot_tokenlabel(ph) );
  issuer = cert_info((X509 *)get_X509_certificate(chosen_cert), CERT_ISSUER,
                     ALGORITHM_NULL);
  if (issuer)
	  _pam_putenv( pamh, configuration, "PKCS11_LOGIN_CERT_ISSUER",
				   issuer[0] );
  serial = cert_info((X509 *)get_X509_certificate(chosen_cert), CERT_SERIAL,
                     ALGORITHM_NULL);
  if (serial)
	  _pam_putenv( pamh, configuration, "PKCS11_LOGIN_CERT_SERIAL",
				   serial[0] );

  int pin_status = PIN_OK;
  if (!pin_to_be_changed && lowlevel && lowlevel->funcs.pin_status) {
      pin_status = (*lowlevel->funcs.pin_status)(lowlevel->funcs.context, slot_num, 0);
      if (pin_status < 0) {
          ERR1("pin_status() from %s failed", lowlevel->module_name);
          if (!configuration->quiet) {
              _pam_syslog(pamh, LOG_ERR, "pin_status() from %s failed",
                         lowlevel->module_name);
          }
      } else {
          DBG1 ("PIN status: %d", pin_status);
          pin_to_be_changed = 1;
      }
  } else if (pin_to_be_changed) {
      pin_status = PIN_DEFAULT;
  }

  /* unload lowlevel modules */
  unload_llmodule( lowlevel );
  /* unload mapper modules */
  unload_mappers();

  if (pin_to_be_changed) {
      pam_prompt (pamh, PAM_TEXT_INFO, NULL,
                  PAM_EXPIRED ?
                    _(configuration->prompts.pin_expired) :
                    _(configuration->prompts.pin_to_be_changed));
  }

  /* close pkcs #11 session */
  rv = pkcs11_close_session( pamh, configuration, ph );
  if (rv != 0)
      goto auth_failed_nopw;

  rv = PAM_SUCCESS;
  if (pin_to_be_changed && configuration->force_pin_change) {
      rv = pam_set_pin( pamh, ph, slot_num, configuration, password, 0 );
  }

  if ( password ) {
      cleanse( password, strlen(password) );
      free( password );
      password = NULL;
  }

  /* release pkcs #11 module */
  DBG("releasing pkcs #11 module...");
  release_pkcs11_module(ph);

  if (rv == PAM_SUCCESS) {
      DBG("authentication succeeded");
  }
  return rv;

auth_failed_nopw:
    unload_llmodule( lowlevel );
    unload_mappers();
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    if ( password ) {
        cleanse( password, strlen(password) );
        free( password );
    }

	if (PAM_IGNORE == pkcs11_pam_fail)
		goto exit_ignore;
	else
		return pkcs11_pam_fail;

auth_failed_wrongpw:
    unload_mappers();
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    if ( password ) {
        cleanse( password, strlen(password) );
        free( password );
    }
    return PAM_AUTH_ERR;

 exit_ignore:
	pam_prompt( pamh, PAM_TEXT_INFO, NULL,
				_(configuration->prompts.auth_cancelled) );
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  DBG("pam_sm_setcred() called");
  /* Actually, we should return the same value as pam_sm_authenticate(). */
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pm_sm_acct_mgmt() is not implemented in this module");
  _pam_syslog(pamh, LOG_WARNING,
             "Function pm_sm_acct_mgmt() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pam_sm_open_session() is not implemented in this module");
  _pam_syslog(pamh, LOG_WARNING,
             "Function pm_sm_open_session() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pam_sm_close_session() is not implemented in this module");
  _pam_syslog(pamh, LOG_WARNING,
           "Function pm_sm_close_session() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  char *login_token_name;
  login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");

  {
      int rv; unsigned int slot_num;
      struct configuration_st *configuration;
      pkcs11_handle_t *ph;
      
      if (flags & PAM_PRELIM_CHECK) {
          return PAM_SUCCESS;
      }

      configuration = pk_configure(argc,argv);
      if (!configuration ) {
          ERR("Error setting configuration parameters");
          return PAM_AUTHINFO_UNAVAIL;
      }
      
      rv = pkcs11_module_load_init( pamh, configuration, &ph );
      if ( rv != 0 ) {
          return rv;
      }

      rv = pkcs11_find_slot( pamh, configuration, login_token_name, ph,
                             &slot_num, 0 );
      if ( rv != 0 ) {
          ERR("No smartcard found");
          if (!configuration->quiet) {
              _pam_syslog(pamh, LOG_ERR, "No smartcard found");
          }
          if ( configuration->card_only || login_token_name ) {
              pam_prompt(pamh, PAM_ERROR_MSG, NULL,
                         _(configuration->prompts.no_card_err));
              sleep(configuration->err_display_time);
          }          
          release_pkcs11_module(ph);
          if ( configuration->card_only || login_token_name ) {
              return PAM_AUTHINFO_UNAVAIL;
          } else {
              return PAM_IGNORE;
          }
      }

      int init_pin = 0;

      int _init_pin = (pam_getenv(pamh, "INIT_PIN") != NULL);
      if (!_init_pin) _init_pin = (pam_getenv(pamh, "PAM_RESET_AUTHTOK") != NULL);
      if (!_init_pin) _init_pin = (getenv("PKCS11_INIT_PIN") != NULL);

      if (_init_pin && configuration->reset_pin_low) {
          rv = get_slot_user_pin_count_low(ph);
          if (rv) {
              if (rv < 0) report_pkcs11_lib_error(pamh, "get_slot_user_pin_count_low", configuration);
              DBG("Set InitPIN mode on due to incorrect login attempts");
              init_pin = 1;
          }
      }

      int locked = 0;
      if (!init_pin) {
          rv = get_slot_user_pin_locked(ph);
          if (rv) {
              if (rv < 0) report_pkcs11_lib_error(pamh, "get_slot_user_pin_locked", configuration);
              if (!_init_pin || !configuration->reset_pin_locked) {
                  locked = 1;
              } else {
                  init_pin = 1;
              }
          }
      }

      if (flags & PAM_CHANGE_EXPIRED_AUTHTOK) {
          rv = get_slot_user_pin_to_be_changed(ph);
          if (rv < 0) {
              report_pkcs11_lib_error(pamh,
                                      "get_slot_user_pin_to_be_changed",
                                      configuration);
              return PAM_AUTHINFO_UNAVAIL;
          }
          if (!rv) {
              return PAM_SUCCESS;
          }
      }

      pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                 init_pin ?
                   _(configuration->prompts.user_pin_reset) :
                   (locked ?
                    _(configuration->prompts.changing_user_pin_locked) :
                    _(configuration->prompts.changing_user_pin)));

      if (!locked) {
          rv = pam_set_pin( pamh, ph, slot_num, configuration, NULL,
                            init_pin );
      } else {
          pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                     _(configuration->prompts.pin_locked));
          sleep(configuration->err_display_time);
          rv = PAM_AUTHINFO_UNAVAIL;
      }

      release_pkcs11_module( ph );

      return rv;
  } else {
      return PAM_IGNORE;
  }
}

static
int pam_do_login( pam_handle_t *pamh, pkcs11_handle_t *ph,
                  struct configuration_st *configuration,
                  const char *pass, int init_pin, int final_try )
{
	int rv;

	if ( init_pin ) {
        rv = pkcs11_login_so( ph, pass );
    } else {
        rv = pkcs11_login( ph, pass );
    }

	if ( rv != 0 ) {
		ERR2( "%sLogin failed: %s", init_pin ? "SO " : "",
			  get_error() );
		if ( !configuration->quiet ) {
			_pam_syslog( pamh, LOG_ERR, "%sLogin failed: %s",
						init_pin ? "SO " : "",
						get_error() );
            if (final_try) {
                pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                           _(configuration->prompts.wrong_pin_locked));
            } else {
                pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                           _(configuration->prompts.wrong_pin));
            }
            sleep(configuration->err_display_time);
        }
	}

	return rv;
}

static int pam_do_set_pin( pam_handle_t *pamh,
                           pkcs11_handle_t *ph,
                           struct lowlevel_instance *lowlevel,
                           unsigned int slot_num,
                           struct configuration_st *configuration,
                           char *old_pass,
                           int init_pin )
{
    int rv;
    int clean_old_pass = (old_pass == NULL);
    char *new_pass;
    int logged_in = 0;

    int final_try = check_warn_pin_count( pamh, ph, lowlevel, configuration,
                                          slot_num );

    rv = get_slot_protected_authentication_path( ph );
    if ((-1 == rv) || (0 == rv)) {
        /* no CKF_PROTECTED_AUTHENTICATION_PATH */
        char password_prompt[128];
        char *confirm;

        if (!old_pass) {
            /* Old PIN */
            snprintf(password_prompt, sizeof(password_prompt),
                     init_pin ?
                       _(configuration->prompts.enter_so_pin) :
                       _(configuration->prompts.enter_old_pin),
                     _(configuration->token_type));
            rv = pam_get_pwd(pamh, &old_pass, password_prompt,
                             0, PAM_AUTHTOK);

            if (rv != PAM_SUCCESS) {
                _get_pwd_error( pamh, configuration, rv );
                return PAM_AUTHTOK_RECOVERY_ERR;
            }

            rv = check_pwd( pamh, configuration, old_pass );
            if ( rv != 0 ) {
                if (clean_old_pass && old_pass) {
                    cleanse( old_pass, strlen(old_pass) );
                    free( old_pass );
                }
                return PAM_AUTHTOK_RECOVERY_ERR;
            }
        }

        if ( configuration->check_pin_early ) {
			rv = pam_do_login( pamh, ph, configuration,
                               old_pass, init_pin, final_try );
			if ( rv == 0 ) {
				logged_in = 1;
			} else {
				if (clean_old_pass && old_pass) {
					cleanse( old_pass, strlen(old_pass) );
					free( old_pass );
				}
				return PAM_AUTHTOK_RECOVERY_ERR;
			}
		}

        /* New PIN */
        snprintf(password_prompt, sizeof(password_prompt),
                 _(configuration->prompts.enter_new_pin),
                 _(configuration->token_type));
        rv = pam_get_pwd(pamh, &new_pass, password_prompt,
                         0, PAM_AUTHTOK);

        if (rv != PAM_SUCCESS) {
            _get_pwd_error( pamh, configuration, rv );
            return PAM_AUTHTOK_ERR;
        }

        rv = check_pwd( pamh, configuration, new_pass );
        if ( rv != 0 ) {
            if (clean_old_pass && old_pass) {
                cleanse( old_pass, strlen(old_pass) );
                free( old_pass );
            }
            if ( new_pass ) {
                cleanse( new_pass, strlen(new_pass) );
                free( new_pass );
            }
            return PAM_AUTHTOK_ERR;
        }

        /* Confirm new PIN */
        snprintf(password_prompt, sizeof(password_prompt),
                 _(configuration->prompts.confirm_pin));
        rv = pam_get_pwd(pamh, &confirm, password_prompt,
                         0, PAM_AUTHTOK);

        if (rv != PAM_SUCCESS) {
            _get_pwd_error( pamh, configuration, rv );
            if (clean_old_pass && old_pass) {
                cleanse( old_pass, strlen(old_pass) );
                free( old_pass );
            }
            cleanse( new_pass, strlen(new_pass) );
            free( new_pass );
            return PAM_AUTHTOK_ERR;
        }

        if ( strcmp(new_pass, confirm) != 0 ) {
            ERR("Confirm PIN mismatch");
            if (!configuration->quiet) {
                _pam_syslog(pamh, LOG_ERR, "Confirm PIN mismatch");
            }
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _(configuration->prompts.confirm_pin_mismatch));
            sleep(configuration->err_display_time);
            rv = PAM_AUTHTOK_ERR;
        }

#ifdef ENABLE_PWQUALITY
          if ( rv == 0 && configuration->pwq ) {
              void *auxerror;
              rv = pwquality_check( configuration->pwq, new_pass,
                                    init_pin ? NULL : old_pass,
                                    NULL, &auxerror );
              if ( rv < 0 ) {
                  const char *err_text =
                      pwquality_strerror( NULL, 0, rv, auxerror );
                  ERR1("PIN quality check failed: %s", err_text);
                  if (!configuration->quiet) {
                      _pam_syslog(pamh, LOG_ERR,
                                 "PIN quality check failed: %s", err_text);
                  }
                  pam_prompt( pamh, PAM_ERROR_MSG, NULL,
                              _(configuration->prompts.pwquality_err),
                              err_text );
                  sleep( configuration->err_display_time );
                  rv = PAM_AUTHTOK_ERR;
              } else {
                  rv = 0;
              }
          }
#endif

          if ( rv ) {
            if (clean_old_pass && old_pass) {
                cleanse( old_pass, strlen(old_pass) );
                free( old_pass );
            }
            cleanse( new_pass, strlen(new_pass) );
            free( new_pass );
            cleanse( confirm, strlen(confirm) );
            free( confirm );
            return PAM_AUTHTOK_ERR;
        } else {
            cleanse( confirm, strlen(confirm) );
            free( confirm );
        }
    } else {
        pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                   _(configuration->prompts.change_on_pinpad),
                   _(configuration->token_type));
        old_pass = NULL;
        new_pass = NULL;
    }

    if ( !logged_in ) {
        rv = pam_do_login( pamh, ph, configuration,
                           old_pass, init_pin, final_try );
        if ( rv == 0 ) logged_in = 1;
    }
    if ( rv == 0 ) {
        if (init_pin) {
            rv = pkcs11_initpin( ph, new_pass );
        } else {
            rv = pkcs11_setpin( ph, old_pass, new_pass );
        }
    }

    if (clean_old_pass && old_pass) {
        cleanse( old_pass, strlen(old_pass) );
        free( old_pass );
    }
    if ( new_pass ) {
        cleanse( new_pass, strlen(new_pass) );
        free( new_pass );
    }

    if ( rv == 0 ) {
        return PAM_SUCCESS;
    } else if ( logged_in ) {
        ERR1("C_%PIN error", init_pin ? "Init" : "Set");
        if (!configuration->quiet) {
            _pam_syslog(pamh, LOG_ERR, "C_%sPIN error",
                       init_pin ? "Init" : "Set");
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _("Error: Unable to set new PIN"));
            sleep(configuration->err_display_time);
        }

        if (final_try) {
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       init_pin ?
                         _(configuration->prompts.so_pin_change_err_locked) :
                         _(configuration->prompts.pin_change_err_locked));
        } else {
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       init_pin ?
                         _(configuration->prompts.so_pin_change_err) :
                         _(configuration->prompts.pin_change_err));
        }

        sleep(configuration->err_display_time);
        return PAM_AUTHTOK_ERR;
    } else {
        return PAM_AUTHTOK_ERR;
    }
}

static int pam_set_pin( pam_handle_t *pamh,
                        pkcs11_handle_t *ph,
                        unsigned int slot_num,
                        struct configuration_st *configuration,
                        char *old_pass,
                        int init_pin )
{
    int rv;

    /* load lowlevel modules */
    struct lowlevel_instance *lowlevel = load_lowlevel( configuration->ctx, ph );

    rv = pkcs11_open_session( pamh, configuration, ph, slot_num, 1 );
    if (rv != 0) {
        return PAM_AUTHINFO_UNAVAIL;
    }

#ifdef ENABLE_PWQUALITY
    if ( configuration->pwquality_config ) {
        void *auxerror;
        configuration->pwq = pwquality_default_settings();
        rv = pwquality_read_config( configuration->pwq,
                                    configuration->pwquality_config,
                                    &auxerror );
        if ( rv ) {
            const char *err_text = pwquality_strerror( NULL, 0, rv, auxerror );
            ERR1("Error reading libpwquality config: %s", err_text);
            if (!configuration->quiet) {
                _pam_syslog(pamh, LOG_ERR,
                           "Error reading libpwquality config: %s",
                           err_text);
            }
            rv = PAM_AUTHINFO_UNAVAIL;
        }
    }
#endif

    if ( rv == 0 ) {
        rv = pam_do_set_pin( pamh, ph, lowlevel, slot_num,
                             configuration, old_pass, init_pin );
    }

#ifdef ENABLE_PWQUALITY
    if ( configuration->pwq )
        pwquality_free_settings( configuration->pwq );
#endif

    pkcs11_close_session( pamh, configuration, ph );

    /* unload lowlevel modules */
    unload_llmodule( lowlevel );

    return rv;
}

#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_group_modstruct = {
  "pam_pkcs11",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};
#endif
