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
  char text[128];

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
pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
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

  va_start(va, fmt);
  ret = pam_vprompt(pamh, style, &response, fmt, va);
  va_end(va);

  free(response);

  return ret;
}
#endif


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
        pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                   _("Error 2316: password could not be read"));
        sleep(configuration->err_display_time);
    }
    pam_syslog(pamh, LOG_ERR,
               "pam_get_pwd() failed: %s", pam_strerror(pamh, rv));
}

static int check_pwd( pam_handle_t *pamh,
                      struct configuration_st *configuration,
                      char *password )
{
#ifdef DEBUG_SHOW_PASSWORD
    DBG1("password = [%s]", password);
#endif

    /* check password length */
    if ( !configuration->nullok && strlen(password) == 0 ) {
        memset(password, 0, strlen(password));
        pam_syslog(pamh, LOG_ERR,
                   "password length is zero but the 'nullok' " \
                   "argument was not defined.");
        if (!configuration->quiet) {
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _("Error 2318: Empty smartcard PIN not allowed."));
            sleep(configuration->err_display_time);
        }
        return PAM_AUTH_ERR;
    }

    return 0;
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
            pam_syslog(pamh, LOG_ERR,
                       "load_pkcs11_module() failed loading %s: %s",
                       configuration->pkcs11_modulepath, get_error());
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _("Error 2302: PKCS#11 module failed loading"));
            sleep(configuration->err_display_time);
        }
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* initialise pkcs #11 module */
    DBG("initializing pkcs #11 module...");
    rv = init_pkcs11_module( *ph, configuration->support_threads );

    if (rv != 0) {
        release_pkcs11_module( *ph );
        ERR1("init_pkcs11_module() failed: %s", get_error());
        if (!configuration->quiet) {
            pam_syslog(pamh, LOG_ERR,
                       "init_pkcs11_module() failed: %s",
                       get_error());
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _("Error 2304: PKCS#11 module could not be initialized"));
            sleep(configuration->err_display_time);
        }
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
            pam_syslog(pamh, LOG_ERR, "open_pkcs11_session() failed: %s", get_error());
            pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2312: open PKCS#11 session failed"));
            sleep(configuration->err_display_time);
        }
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
			pam_syslog(pamh, LOG_ERR, "close_pkcs11_module() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, ("Error 2344: Closing PKCS#11 session failed"));
			sleep(configuration->err_display_time);
		}
    }

    return rv;
}

static void report_pkcs11_lib_error(pam_handle_t *pamh,
                                    const char *func,
                                    struct configuration_st *configuration)
{
    ERR2("%s() failed: %s", func, get_error());
    if (!configuration->quiet) {
        pam_syslog(pamh, LOG_ERR, "%s() failed: %s", func, get_error());
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
                   _("WARNING! PIN FINAL TRY!!!"));
        sleep(configuration->err_display_time);
    } else {
        rv = get_slot_user_pin_count_low(ph);
        if (rv) {
            if (rv < 0) report_pkcs11_lib_error(pamh, "get_slot_user_pin_count_low", configuration);

            int pins_left = -1;
            if ( lowlevel && lowlevel->funcs.pin_count) {
                pins_left = (*lowlevel->funcs.pin_count)(lowlevel->funcs.context, slot_num, 0);
                if (pins_left >= 0) {
                    pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                               (pins_left < configuration->pin_count_low) ?
                                 _("WARNING! There were incorrect login attempts! Only %d PIN attempts left!") :
                                 _("WARNING! There were incorrect login attempts! %d PIN attempts left."),
                               pins_left);
                } else {
                    ERR1("pin_count() from %s failed", lowlevel->module_name);
                    if (!configuration->quiet) {
                        pam_syslog(pamh, LOG_ERR, "pin_count() from %s failed",
                                   lowlevel->module_name);
                    }
                }
            }

            if (pins_left < 0) {
                pam_prompt(pamh, PAM_ERROR_MSG, NULL,
                           _("WARNING! There were incorrect login attempts!"));
                sleep(configuration->err_display_time);
            }
        }
    }

    return final_try;
}

static int pam_set_pin( pam_handle_t *pamh, pkcs11_handle_t *ph,
                        unsigned int slot_num,
                        struct configuration_st *configuration,
                        char *old_pass,
                        int init_pin );

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int i, rv;
  const char *user = NULL;
  char *password;
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
  char env_temp[256] = "";
  char **issuer, **serial;
  const char *login_token_name = NULL;
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

  /* call configure routines */
  configuration = pk_configure(argc,argv);
  if (!configuration ) {
	ERR("Error setting configuration parameters");
	return PAM_AUTHINFO_UNAVAIL;
  }

  /* Either slot_description or slot_num, but not both, needs to be used */
  if ((configuration->slot_description != NULL && configuration->slot_num != -1) || (configuration->slot_description == NULL && configuration->slot_num == -1)) {
	ERR("Error setting configuration parameters");
	return PAM_AUTHINFO_UNAVAIL;
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
	char *service;
	if (configuration->screen_savers) {
	    DBG("Is it a screen saver?");
		pam_get_item(pamh, PAM_SERVICE, &service);
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
			  pam_syslog(pamh, LOG_ERR,
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
      pam_syslog(pamh,LOG_ERR, "Failed to initialize crypto");
    return pkcs11_pam_fail;
  }
  
  /* look to see if username is already set */
  pam_get_item(pamh, PAM_USER, &user);
  if (user) {
      DBG1("explicit username = [%s]", user);
  }
  
  /* if we are using a screen saver, and we didn't log in using the smart card
   * drop to the next pam module.  */
  if (is_a_screen_saver && !login_token_name) {
    return PAM_IGNORE;
  }

  rv = pkcs11_module_load_init( pamh, configuration, &ph );
  if ( rv != 0 ) {
      return rv;
  }

  rv = pkcs11_find_slot( pamh, configuration, login_token_name, ph,
                         &slot_num, 0 );

  if (rv != 0) {
    if (!configuration->card_only) {
        /* If the login isn't restricted to card-only, then proceed
           to the next auth. module quietly. */
        release_pkcs11_module(ph);
        return PAM_IGNORE;
    }

    if (!configuration->wait_for_card) {
        ERR("no suitable token available");
        if (!configuration->quiet) {
            pam_syslog(pamh, LOG_ERR, "no suitable token available");
        }
    }

    if (configuration->wait_for_card) {
        if (login_token_name) {
            pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                       _("Please insert your smart card called \"%.32s\"."),
                       login_token_name);
        } else {
            pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                       _("Please insert your smart card."));
        }

        rv = pkcs11_find_slot( pamh, configuration, login_token_name, ph,
                               &slot_num, 1 );
    }
  }

  if (rv != 0) {
      /* Still no card */
      if (pkcs11_pam_fail != PAM_IGNORE) {
          if (!configuration->quiet) {
              pam_prompt(pamh, PAM_ERROR_MSG,
                         NULL, _("Error 2308: No smartcard found"));
              sleep(configuration->err_display_time);
          }
      } else {
          pam_prompt(pamh, PAM_TEXT_INFO,
                     NULL, _("No smartcard found"));
      }
      release_pkcs11_module(ph);
      return pkcs11_pam_fail;
  }

  pam_prompt(pamh, PAM_TEXT_INFO, NULL,
             _("%s found."), _(configuration->token_type));

  /* open pkcs #11 session */
  rv = open_pkcs11_session(ph, slot_num);
  if (rv != 0) {
    release_pkcs11_module(ph);
    return pkcs11_pam_fail;
  }

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
		pam_syslog(pamh, LOG_ERR, "get_slot_login_required() failed: %s", get_error());
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2314: Slot login failed"));
		sleep(configuration->err_display_time);
	}
    release_pkcs11_module(ph);
    return pkcs11_pam_fail;
  } else if (rv) {
      pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                 pin_locked ?
                   _("Welcome %.32s! PIN is locked!") :
                   _("Welcome %.32s!"),
                 get_slot_tokenlabel(ph));

      if (pin_locked) {
          pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                     _("User PIN is locked!"));
          sleep(configuration->err_display_time);
          release_pkcs11_module(ph);
          return pkcs11_pam_fail;
      }

      final_try = check_warn_pin_count( pamh, ph, lowlevel, configuration,
                                        slot_num );

	/* no CKF_PROTECTED_AUTHENTICATION_PATH */
	rv = get_slot_protected_authentication_path(ph);
	if ((-1 == rv) || (0 == rv))
	{
		char password_prompt[128];

		snprintf(password_prompt,  sizeof(password_prompt), _("%s PIN: "), _(configuration->token_type));
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
			release_pkcs11_module(ph);
			return pkcs11_pam_fail;
		}

        rv = check_pwd( pamh, configuration, password );
        if ( rv != 0 ) {
			release_pkcs11_module(ph);
            if ( password ) {
                memset( password, 0, strlen(password) );
                free( password );
            }
			return PAM_AUTH_ERR;
		}
	}
	else
	{
		pam_prompt(pamh, PAM_TEXT_INFO, NULL,
			_("Enter your %s PIN on the pinpad"), _(configuration->token_type));
		/* use pin pad */
		password = NULL;
	}

    /* call pkcs#11 login to ensure that the user is the real owner of the card
     * we need to do thise before get_certificate_list because some tokens
     * can not read their certificates until the token is authenticated */
    rv = pkcs11_login(ph, password);
    /* erase and free in-memory password data asap */
	if (password && !pin_to_be_changed)
	{
		cleanse(password, strlen(password));
		free(password);
	}
    if (rv != 0) {
      ERR1("open_pkcs11_login() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "open_pkcs11_login() failed: %s", get_error());
        }
        if ( lowlevel && lowlevel->module_data && lowlevel->module_data->pin_count) {
            int pins_left = (*lowlevel->module_data->pin_count)(lowlevel->module_data->context, slot_num, 0);
            if (pins_left > 0) {
                if (pins_left < configuration->pin_count_low) {
                    pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                               pins_left > 1 ?
                                 _("Error 2320.1: Wrong smartcard PIN. Only %i attempts left!"):
                                 _("Error 2320.1: Wrong smartcard PIN. Only 1 attempt left!"),
                               pins_left);
                } else {
                    pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                               pins_left > 1 ?
                                 _("Error 2320.2: Wrong smartcard PIN. %i attempts left!"):
                                 _("Error 2320.2: Wrong smartcard PIN. 1 attempt left!"),
                               pins_left);
                }
            } else if (pins_left == 0) {
                pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                           _("Error 2320.3: Wrong smartcard PIN. The PIN is locked now!"));
            } else {
                ERR1("pin_count() from %s failed", lowlevel->module_name);
                if (!configuration->quiet) {
                    pam_syslog(pamh, LOG_ERR, "pin_count() from %s failed",
                               lowlevel->module_name);
                }
            }
        } else {
            if (final_try) {
                pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                           _("Error 2320.3: Wrong smartcard PIN. The PIN is locked now!"));
            } else {
                pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2320: Wrong smartcard PIN"));
            }
        }
        sleep(configuration->err_display_time);
        goto auth_failed_wrongpw;
    }
  }

  cert_list = get_certificate_list(ph, &ncert);
  if (rv<0) {
    ERR1("get_certificate_list() failed: %s", get_error());
    if (!configuration->quiet) {
		pam_syslog(pamh, LOG_ERR, "get_certificate_list() failed: %s", get_error());
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2322: No certificate found"));
		sleep(configuration->err_display_time);
	}
    goto auth_failed_nopw;
  }

  /* load mapper modules */
  load_mappers(configuration->ctx);
  /* load lowlevel modules */
  struct lowlevel_instance *lowlevel = load_lowlevel( configuration->ctx, ph );

  /* find a valid and matching certificates */
  for (i = 0; i < ncert; i++) {
    X509 *x509 = (X509 *)get_X509_certificate(cert_list[i]);
    if (!x509 ) continue; /* sanity check */
    DBG1("verifying the certificate #%d", i + 1);
	if (!configuration->quiet) {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("verifying certificate"));
	}

      /* verify certificate (date, signature, CRL, ...) */
      rv = verify_certificate(x509,&configuration->policy);
      if (rv < 0) {
        ERR1("verify_certificate() failed: %s", get_error());
        if (!configuration->quiet) {
          pam_syslog(pamh, LOG_ERR,
                   "verify_certificate() failed: %s", get_error());
			switch (rv) {
				case -2: // X509_V_ERR_CERT_HAS_EXPIRED:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2324: Certificate has expired"));
					break;
				case -3: // X509_V_ERR_CERT_NOT_YET_VALID:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2326: Certificate not yet valid"));
					break;
				case -4: // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2328: Certificate signature invalid"));
					break;
				default:
					pam_prompt(pamh, PAM_ERROR_MSG , NULL,
						_("Error 2330: Certificate invalid"));
					break;
			}
			sleep(configuration->err_display_time);
		}
        continue; /* try next certificate */
      } else if (rv != 1) {
        ERR1("verify_certificate() failed: %s", get_error());
        continue; /* try next certificate */
      }

    /* CA and CRL verified, now check/find user */

    if ( is_spaced_str(user) ) {
      /*
	if provided user is null or empty extract and set user
	name from certificate
      */
	DBG("Empty login: try to deduce from certificate");
	user=find_user(x509);
	if (!user) {
          ERR2("find_user() failed: %s on cert #%d", get_error(),i+1);
          if (!configuration->quiet)
            pam_syslog(pamh, LOG_ERR,
                     "find_user() failed: %s on cert #%d",get_error(),i+1);
	  continue; /* try on next certificate */
	} else {
          DBG1("certificate is valid and matches user %s",user);
	  /* try to set up PAM user entry with evaluated value */
	  rv = pam_set_item(pamh, PAM_USER,(const void *)user);
	  if (rv != PAM_SUCCESS) {
	    ERR1("pam_set_item() failed %s", pam_strerror(pamh, rv));
            if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR,
                       "pam_set_item() failed %s", pam_strerror(pamh, rv));
				pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2332: setting PAM userentry failed"));
				sleep(configuration->err_display_time);
			}
	    goto auth_failed_nopw;
	}
          chosen_cert = cert_list[i];
          break; /* end loop, as find user success */
      }
    } else {
      /* User provided:
         check whether the certificate matches the user */
        rv = match_user(x509, user);
        if (rv < 0) { /* match error; abort and return */
          ERR1("match_user() failed: %s", get_error());
			if (!configuration->quiet) {
				pam_syslog(pamh, LOG_ERR, "match_user() failed: %s", get_error());
				pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2334: No matching user"));
				sleep(configuration->err_display_time);
			}
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
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR,
				"no valid certificate which meets all requirements found");
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2336: No matching certificate found"));
		sleep(configuration->err_display_time);
	}
    goto auth_failed_nopw;
  }


  /* if signature check is enforced, generate random data, sign and verify */
  if (configuration->policy.signature_policy) {
		pam_prompt(pamh, PAM_TEXT_INFO, NULL, _("Checking signature"));


#ifdef notdef
    rv = get_private_key(ph);
    if (rv != 0) {
      ERR1("get_private_key() failed: %s", get_error());
      if (!configuration->quiet)
        pam_syslog(pamh, LOG_ERR,
                 "get_private_key() failed: %s", get_error());
      goto auth_failed_nopw;
    }
#endif

    /* read random value */
    rv = get_random_value(random_value, sizeof(random_value));
    if (rv != 0) {
      ERR1("get_random_value() failed: %s", get_error());
		if (!configuration->quiet){
			pam_syslog(pamh, LOG_ERR, "get_random_value() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2338: Getting random value failed"));
			sleep(configuration->err_display_time);
		}
      goto auth_failed_nopw;
    }

    /* sign random value */
    signature = NULL;
    rv = sign_value(ph, chosen_cert, random_value, sizeof(random_value),
		    &signature, &signature_length);
    if (rv != 0) {
      ERR1("sign_value() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "sign_value() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2340: Signing failed"));
			sleep(configuration->err_display_time);
		}
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
      close_pkcs11_session(ph);
      release_pkcs11_module(ph);
      ERR1("verify_signature() failed: %s", get_error());
		if (!configuration->quiet) {
			pam_syslog(pamh, LOG_ERR, "verify_signature() failed: %s", get_error());
			pam_prompt(pamh, PAM_ERROR_MSG , NULL, _("Error 2342: Verifying signature failed"));
			sleep(configuration->err_display_time);
		}
      return PAM_AUTH_ERR;
    }

  } else {
      DBG("Skipping signature check");
  }

  /*
   * fill in the environment variables.
   */
  snprintf(env_temp, sizeof(env_temp) - 1,
	   "PKCS11_LOGIN_TOKEN_NAME=%.*s",
	   (int)((sizeof(env_temp) - 1) - strlen("PKCS11_LOGIN_TOKEN_NAME=")),
	   get_slot_tokenlabel(ph));
  rv = pam_putenv(pamh, env_temp);

  if (rv != PAM_SUCCESS) {
    ERR1("could not put token name in environment: %s",
         pam_strerror(pamh, rv));
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "could not put token name in environment: %s",
           pam_strerror(pamh, rv));
  }

  issuer = cert_info((X509 *)get_X509_certificate(chosen_cert), CERT_ISSUER,
                     ALGORITHM_NULL);
  if (issuer) {
    snprintf(env_temp, sizeof(env_temp) - 1,
	   "PKCS11_LOGIN_CERT_ISSUER=%.*s",
	   (int)((sizeof(env_temp) - 1) - strlen("PKCS11_LOGIN_CERT_ISSUER=")),
	   issuer[0]);
    rv = pam_putenv(pamh, env_temp);
  } else {
    ERR("couldn't get certificate issuer.");
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "couldn't get certificate issuer.");
  }

  if (rv != PAM_SUCCESS) {
    ERR1("could not put cert issuer in environment: %s",
         pam_strerror(pamh, rv));
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "could not put cert issuer in environment: %s",
           pam_strerror(pamh, rv));
  }

  serial = cert_info((X509 *)get_X509_certificate(chosen_cert), CERT_SERIAL,
                     ALGORITHM_NULL);
  if (serial) {
    snprintf(env_temp, sizeof(env_temp) - 1,
	   "PKCS11_LOGIN_CERT_SERIAL=%.*s",
	   (int)((sizeof(env_temp) - 1) - strlen("PKCS11_LOGIN_CERT_SERIAL=")),
	   serial[0]);
    rv = pam_putenv(pamh, env_temp);
  } else {
    ERR("couldn't get certificate serial number.");
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "couldn't get certificate serial number.");
  }

  if (rv != PAM_SUCCESS) {
    ERR1("could not put cert serial in environment: %s",
         pam_strerror(pamh, rv));
    if (!configuration->quiet)
      pam_syslog(pamh, LOG_ERR, "could not put cert serial in environment: %s",
           pam_strerror(pamh, rv));
  }

  int pin_status = PIN_OK;
  if (!pin_to_be_changed && lowlevel && lowlevel->funcs.pin_status) {
      pins_status = (*lowlevel->funcs.pin_status)(lowlevel->funcs.context, slot_num, 0);
      if (pins_status < 0) {
          ERR1("pin_status() from %s failed", lowlevel->module_name);
          if (!configuration->quiet) {
              pam_syslog(pamh, LOG_ERR, "pin_status() from %s failed",
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
                    _("User PIN has expired and needs to be changed") :
                    _("User PIN needs to be changed"));
  }

  /* close pkcs #11 session */
  rv = pkcs11_close_session( pamh, configuration, ph );
  if (rv != 0) {
    release_pkcs11_module(ph);
    return pkcs11_pam_fail;
  }

  rv = PAM_SUCCESS;
  if (pin_to_be_changed && configuration->force_pin_change) {
      rv = pam_set_pin( pamh, ph, slot_num, configuration, password, 0 );
      if ( password ) {
          memset( password, 0, strlen(password) );
          free( password );
      }
  }

  /* release pkcs #11 module */
  DBG("releasing pkcs #11 module...");
  release_pkcs11_module(ph);

  if (rv == PAM_SUCCESS) {
      DBG("authentication succeeded");
  }
  return rv;

  /* quick and dirty fail exit point */
  cleanse(password, strlen(password));
  free(password); /* erase and free in-memory password data */

auth_failed_nopw:
    unload_llmodule( lowlevel );
    unload_mappers();
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    return pkcs11_pam_fail;

auth_failed_wrongpw:
    unload_mappers();
    close_pkcs11_session(ph);
    release_pkcs11_module(ph);
    return PAM_AUTH_ERR;
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
  pam_syslog(pamh, LOG_WARNING,
             "Function pm_sm_acct_mgmt() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pam_sm_open_session() is not implemented in this module");
  pam_syslog(pamh, LOG_WARNING,
             "Function pm_sm_open_session() is not implemented in this module");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  ERR("Warning: Function pam_sm_close_session() is not implemented in this module");
  pam_syslog(pamh, LOG_WARNING,
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
              pam_syslog(pamh, LOG_ERR, "No smartcard found");
          }
          if ( configuration->card_only || login_token_name ) {
              pam_prompt(pamh, PAM_ERROR_MSG, NULL,
                         _("Error 2310: No smartcard found"));
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
                   _("User PIN reset") :
                   (locked ?
                    _("Changing the user PIN is blocked") :
                    _("Changing the user PIN")));

      if (!locked) {
          rv = pam_set_pin( pamh, ph, slot_num, configuration, NULL,
                            init_pin );
      } else {
          pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                     _("User PIN is locked!"));
          sleep(configuration->err_display_time);
          rv = PAM_AUTHINFO_UNAVAIL;
      }

      release_pkcs11_module( ph );

      return rv;
  } else {
      return PAM_IGNORE;
  }
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
                     _("Old %s PIN: "), _(configuration->token_type));
            rv = pam_get_pwd(pamh, &old_pass, password_prompt,
                             0, PAM_AUTHTOK);

            if (rv != PAM_SUCCESS) {
                _get_pwd_error( pamh, configuration, rv );
                return PAM_AUTHTOK_RECOVERY_ERR;
            }

            rv = check_pwd( pamh, configuration, old_pass );
            if ( rv != 0 ) {
                if (clean_old_pass && old_pass) {
                    memset( old_pass, 0, strlen(old_pass) );
                    free( old_pass );
                }
                return PAM_AUTHTOK_RECOVERY_ERR;
            }
        }

        /* New PIN */
        snprintf(password_prompt, sizeof(password_prompt),
                 _("New %s PIN: "), _(configuration->token_type));
        rv = pam_get_pwd(pamh, &new_pass, password_prompt,
                         0, PAM_AUTHTOK);

        if (rv != PAM_SUCCESS) {
            _get_pwd_error( pamh, configuration, rv );
            return PAM_AUTHTOK_ERR;
        }

        rv = check_pwd( pamh, configuration, new_pass );
        if ( rv != 0 ) {
            if (clean_old_pass && old_pass) {
                memset( old_pass, 0, strlen(old_pass) );
                free( old_pass );
            }
            if ( new_pass ) {
                memset( new_pass, 0, strlen(new_pass) );
                free( new_pass );
            }
            return PAM_AUTHTOK_ERR;
        }

        /* Confirm new PIN */
        snprintf(password_prompt, sizeof(password_prompt),
                 _("Confirm new PIN: "));
        rv = pam_get_pwd(pamh, &confirm, password_prompt,
                         0, PAM_AUTHTOK);

        if (rv != PAM_SUCCESS) {
            _get_pwd_error( pamh, configuration, rv );
            if (clean_old_pass && old_pass) {
                memset( old_pass, 0, strlen(old_pass) );
                free( old_pass );
            }
            memset( new_pass, 0, strlen(new_pass) );
            free( new_pass );
            return PAM_AUTHTOK_ERR;
        }

        if ( strcmp(new_pass, confirm) != 0 ) {
            ERR("Confirm PIN mismatch");
            if (!configuration->quiet) {
                pam_syslog(pamh, LOG_ERR, "Confirm PIN mismatch");
                pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                           _("Confirm PIN mismatch"));
                sleep(configuration->err_display_time);
            }
            if (clean_old_pass && old_pass) {
                memset( old_pass, 0, strlen(old_pass) );
                free( old_pass );
            }
            memset( new_pass, 0, strlen(new_pass) );
            free( new_pass );
            memset( confirm, 0, strlen(confirm) );
            free( confirm );
            return PAM_AUTHTOK_ERR;
        } else {
            memset( confirm, 0, strlen(confirm) );
            free( confirm );
        }
    } else {
        pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                   _("Now use the pinpad to change your %s PIN"),
                   _(configuration->token_type));
        old_pass = NULL;
        new_pass = NULL;
    }

    if (init_pin) {
        rv = pkcs11_login_so( ph, old_pass );
        if ( rv == 0 ) {
            rv = pkcs11_initpin( ph, new_pass );
        }
    } else {
        rv = pkcs11_login( ph, old_pass );
        if ( rv == 0 ) {
            rv = pkcs11_setpin( ph, old_pass, new_pass );
        }
    }

    if (clean_old_pass && old_pass) {
        memset( old_pass, 0, strlen(old_pass) );
        free( old_pass );
    }
    if ( new_pass ) {
        memset( new_pass, 0, strlen(new_pass) );
        free( new_pass );
    }

    if ( rv == 0 ) {
        return PAM_SUCCESS;
    } else {
        ERR1("C_%PIN error", init_pin ? "Init" : "Set");
        if (!configuration->quiet) {
            pam_syslog(pamh, LOG_ERR, "C_%sPIN error",
                       init_pin ? "Init" : "Set");
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _("Error: Unable to set new PIN"));
            sleep(configuration->err_display_time);
        }

        if (final_try) {
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _("Error 2320.3: Wrong smartcard PIN. The PIN is locked now!"));
        } else {
            pam_prompt(pamh, PAM_ERROR_MSG , NULL,
                       _("Error 2320: Wrong smartcard PIN"));
        }

        sleep(configuration->err_display_time);
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

    rv = pam_do_set_pin( pamh, ph, lowlevel, slot_num,
                         configuration, old_pass,
                         init_pin );

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
