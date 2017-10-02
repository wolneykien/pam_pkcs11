/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
 * config mgmt copyright (c) 2005 Juan Antonio Martinez <jonsito@teleline.es>
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

#define _PAM_CONFIG_C_

#include <syslog.h>
#include <string.h>
#include "config.h"
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/cert_vfy.h"
#include "pam_config.h"
#include "mapper_mgr.h"

#undef DEBUG_CONFIG

#define N_(string) (string)

/*
* configuration related functions
*/

struct configuration_st configuration;

#ifdef DEBUG_CONFIG
static void display_config (void) {
        DBG1("debug %d",configuration.debug);
        DBG1("nullok %d",configuration.nullok);
        DBG1("try_first_pass %d",configuration.try_first_pass);
        DBG1("use_first_pass %d", configuration.use_first_pass);
        DBG1("use_authok %d", configuration.use_authok);
        DBG1("card_only %d", configuration.card_only);
        DBG1("wait_for_card %d", configuration.wait_for_card);
        DBG1("pkcs11_module %s",configuration.pkcs11_module);
        DBG1("pkcs11_modulepath %s",configuration.pkcs11_modulepath);
        DBG1("slot_description %s",configuration.slot_description);
        DBG1("slot_num %d",configuration.slot_num);
        DBG1("ca_dir %s",configuration.policy.ca_dir);
        DBG1("crl_dir %s",configuration.policy.crl_dir);
        DBG1("nss_dir %s",configuration.policy.nss_dir);
        DBG1("support_threads %d",configuration.support_threads);
        DBG1("ca_policy %d",configuration.policy.ca_policy);
        DBG1("crl_policy %d",configuration.policy.crl_policy);
        DBG1("signature_policy %d",configuration.policy.signature_policy);
        DBG1("ocsp_policy %d",configuration.policy.ocsp_policy);
        DBG1("err_display_time %d", configuration.err_display_time);

        DBG("--- Prompts ---");
        DBG1("start_auth: %s", configuration.prompts.start_auth);
        DBG1("insert_or_enter: %s", configuration.prompts.insert_or_enter);
        DBG1("no_token: %s", configuration.prompts.no_token);
        DBG1("insert_named: %s", configuration.prompts.insert_named);
        DBG1("insert: %s", configuration.prompts.insert);
        DBG1("no_card: %s", configuration.prompts.no_card);
        DBG1("found: %s", configuration.prompts.found);
        DBG1("login_failed: %s", configuration.prompts.login_failed);
        DBG1("welcome: %s", configuration.prompts.welcome);
        DBG1("wrong_pin: %s", configuration.prompts.wrong_pin);
        DBG1("no_cert: %s", configuration.prompts.no_cert);
        DBG1("cert_verif: %s", configuration.prompts.cert_verif);
        DBG1("cert_expired: %s", configuration.prompts.cert_expired);
        DBG1("cert_not_yet: %s", configuration.prompts.cert_not_yet);
        DBG1("cert_inv_sig: %s", configuration.prompts.cert_inv_sig);
        DBG1("cert_inv: %s", configuration.prompts.cert_inv);
        DBG1("no_user_match: %s", configuration.prompts.no_user_match);
        DBG1("no_cert_match: %s", configuration.prompts.no_cert_match);
        DBG1("pin_prompt: %s", configuration.prompts.pin_prompt);
        DBG1("pin_read_err: %s", configuration.prompts.pin_read_err);
        DBG1("empty_pin_err: %s", configuration.prompts.empty_pin_err);
        DBG1("enter_pin: %s", configuration.prompts.enter_pin);
        DBG1("checking_sig: %s", configuration.prompts.checking_sig);
        DBG1("sig_failed: %s", configuration.prompts.sig_failed);
        DBG1("sig_verif_failed: %s", configuration.prompts.sig_verif_failed);
        //DBG1(": %s", configuration.prompts.);
}
#endif

/*
Sets the default prompt values.
*/
static void init_prompts() {
    configuration.prompts.start_auth = "Smartcard authentication starts";
    configuration.prompts.insert_or_enter = "Please insert your %s or enter your username.";
    configuration.prompts.no_token = "Error 2306: No suitable token available";
    configuration.prompts.insert_named = "Please insert your smart card called \"%.32s\".";
    configuration.prompts.insert = "Please insert your smart card.";
    configuration.prompts.no_card = "Error 2308: No smartcard found";
    configuration.prompts.found = "%s found.";
    configuration.prompts.login_failed = "Error 2314: Slot login failed";
    configuration.prompts.welcome = "Welcome %.32s!";
    configuration.prompts.wrong_pin = "Error 2320: Wrong smartcard PIN";
    configuration.prompts.no_cert = "Error 2322: No certificate found";
    configuration.prompts.cert_verif = "verifying certificate";
    configuration.prompts.cert_expired = "Error 2324: Certificate has expired";
    configuration.prompts.cert_not_yet = "Error 2326: Certificate not yet valid";
    configuration.prompts.cert_inv_sig = "Error 2328: Certificate signature invalid";
    configuration.prompts.cert_inv = "Error 2330: Certificate invalid";
    configuration.prompts.no_user_match = "Error 2334: No matching user";
    configuration.prompts.no_cert_match = "Error 2336: No matching certificate found";
    configuration.prompts.pin_prompt = "%s PIN: ";
    configuration.prompts.pin_read_err = "Error 2316: password could not be read";
    configuration.prompts.empty_pin_err = "Error 2318: Empty smartcard PIN not allowed.";
    configuration.prompts.enter_pin = "Enter your %s PIN on the pinpad";
    configuration.prompts.checking_sig = "Checking signature";
    configuration.prompts.sig_failed = "Error 2340: Signing failed";
    configuration.prompts.sig_verif_failed = "Error 2342: Verifying signature failed";
    //configuration.prompts. = ;
}

/*
Sets the default config values.
*/
static void init_configuration() {
    memset(&configuration, 0, sizeof(configuration));
    configuration.config_file = CONFDIR "/pam_pkcs11.conf";
    configuration.pkcs11_module = "default";
    configuration.pkcs11_modulepath = CONFDIR "/pkcs11_module.so";
    configuration.slot_num = -1;

    configuration.policy.crl_policy = CRLP_NONE;
    configuration.policy.ca_dir = CONFDIR "/cacerts";
    configuration.policy.crl_dir = CONFDIR "/crls";
    configuration.policy.nss_dir = CONFDIR "/nssdb";
    configuration.policy.ocsp_policy = OCSP_NONE;

    configuration.token_type = N_("Smart card");

    init_prompts();
}

/*
Parses the configurable prompts
*/
static void parse_prompts(const scconf_block *root) {
    configuration.prompts.start_auth =              \
        scconf_get_str(root, "prompt_start_auth",
                       configuration.prompts.start_auth);

    configuration.prompts.insert_or_enter =             \
        scconf_get_str(root, "prompt_insert_or_enter",
                       configuration.prompts.insert_or_enter);

    configuration.prompts.no_token = \
        scconf_get_str(root, "prompt_no_token",
                       configuration.prompts.no_token);

    configuration.prompts.insert_named = \
        scconf_get_str(root, "prompt_insert_named",
                       configuration.prompts.insert_named);

    configuration.prompts.insert = \
        scconf_get_str(root, "prompt_insert",
                       configuration.prompts.insert);

    configuration.prompts.no_card = \
        scconf_get_str(root, "prompt_no_card",
                       configuration.prompts.no_card);

    configuration.prompts.found = \
        scconf_get_str(root, "prompt_found",
                       configuration.prompts.found);

    configuration.prompts.login_failed = \
        scconf_get_str(root, "prompt_login_failed",
                       configuration.prompts.login_failed);

    configuration.prompts.welcome =                  \
        scconf_get_str(root, "prompt_welcome",
                       configuration.prompts.welcome);

    configuration.prompts.wrong_pin =                  \
        scconf_get_str(root, "prompt_wrong_pin",
                       configuration.prompts.wrong_pin);

    configuration.prompts.no_cert =                  \
        scconf_get_str(root, "prompt_no_cert",
                       configuration.prompts.no_cert);

    configuration.prompts.cert_verif =                  \
        scconf_get_str(root, "prompt_cert_verif",
                       configuration.prompts.cert_verif);

    configuration.prompts.cert_expired =                  \
        scconf_get_str(root, "prompt_cert_expired",
                       configuration.prompts.cert_expired);

    configuration.prompts.cert_not_yet =                  \
        scconf_get_str(root, "prompt_cert_not_yet",
                       configuration.prompts.cert_not_yet);

    configuration.prompts.cert_inv_sig =                  \
        scconf_get_str(root, "prompt_cert_inv_sig",
                       configuration.prompts.cert_inv_sig);

    configuration.prompts.cert_inv =                  \
        scconf_get_str(root, "prompt_cert_inv",
                       configuration.prompts.cert_inv);

    configuration.prompts.no_user_match =                  \
        scconf_get_str(root, "prompt_no_user_match",
                       configuration.prompts.no_user_match);

    configuration.prompts.no_cert_match =                  \
        scconf_get_str(root, "prompt_no_cert_match",
                       configuration.prompts.no_cert_match);

    configuration.prompts.pin_prompt =                  \
        scconf_get_str(root, "prompt_pin_prompt",
                       configuration.prompts.pin_prompt);

    configuration.prompts.pin_read_err =                  \
        scconf_get_str(root, "prompt_pin_read_err",
                       configuration.prompts.pin_read_err);

    configuration.prompts.empty_pin_err =                  \
        scconf_get_str(root, "prompt_empty_pin_err",
                       configuration.prompts.empty_pin_err);

    configuration.prompts.enter_pin =                  \
        scconf_get_str(root, "prompt_enter_pin",
                       configuration.prompts.enter_pin);
    
    configuration.prompts.checking_sig =                  \
        scconf_get_str(root, "prompt_checking_sig",
                       configuration.prompts.checking_sig);

    configuration.prompts.sig_failed =                  \
        scconf_get_str(root, "prompt_sig_failed",
                       configuration.prompts.sig_failed);

    configuration.prompts.sig_verif_failed =                  \
        scconf_get_str(root, "prompt_sig_verif_failed",
                       configuration.prompts.sig_verif_failed);
        
    /* configuration.prompts. =                  \
     *     scconf_get_str(root, "prompt_",
     *                    configuration.prompts.);
     */
}

/*
parse configuration file
*/
static void parse_config_file(void) {
	scconf_block **pkcs11_mblocks,*pkcs11_mblk;
	const scconf_list *mapper_list;
	const scconf_list *policy_list;
 	const scconf_list *screen_saver_list;
 	const scconf_list *tmp;
	scconf_context *ctx;
	const scconf_block *root;
	configuration.ctx = scconf_new(configuration.config_file);
	if (!configuration.ctx) {
           DBG("Error creating conf context");
	   return;
	}
	ctx = configuration.ctx;
	if ( scconf_parse(ctx) <=0 ) {
           DBG1("Error parsing file %s",configuration.config_file);
	   return;
	}
	/* now parse options */
	root = scconf_find_block(ctx, NULL, "pam_pkcs11");
	if (!root) {
           DBG1("pam_pkcs11 block not found in config: %s",configuration.config_file);
	   return;
	}
	configuration.err_display_time =
		scconf_get_int(root,"err_display_time",configuration.err_display_time);
	configuration.nullok =
	    scconf_get_bool(root,"nullok",configuration.nullok);
	configuration.quiet = scconf_get_bool(root,"quiet",configuration.quiet);
	if (configuration.quiet)
	    set_debug_level(-2);
	configuration.debug =
	    scconf_get_bool(root,"debug",configuration.debug);
	if (configuration.debug)
	    set_debug_level(1);
	configuration.use_first_pass =
	    scconf_get_bool(root,"use_first_pass",configuration.use_first_pass);
	configuration.try_first_pass =
	    scconf_get_bool(root,"try_first_pass",configuration.try_first_pass);
	configuration.use_authok =
	    scconf_get_bool(root,"use_authok",configuration.use_authok);
	configuration.card_only =
	    scconf_get_bool(root,"card_only",configuration.card_only);
	configuration.wait_for_card =
	    scconf_get_bool(root,"wait_for_card",configuration.wait_for_card);
	configuration.pkcs11_module = ( char * )
	    scconf_get_str(root,"use_pkcs11_module",configuration.pkcs11_module);
	/* search pkcs11 module options */
	pkcs11_mblocks = scconf_find_blocks(ctx,root,"pkcs11_module",configuration.pkcs11_module);
        if (!pkcs11_mblocks) {
           DBG1("Pkcs11 module name not found: %s",configuration.pkcs11_module);
	} else {
            pkcs11_mblk=pkcs11_mblocks[0]; /* should only be one */
            free(pkcs11_mblocks);
	    if (!pkcs11_mblk) {
               DBG1("No module entry: %s",configuration.pkcs11_module);
	    }
	    configuration.pkcs11_modulepath = (char *)
	        scconf_get_str(pkcs11_mblk,"module",configuration.pkcs11_modulepath);
	    configuration.policy.ca_dir = (char *)
	        scconf_get_str(pkcs11_mblk,"ca_dir",configuration.policy.ca_dir);
	    configuration.policy.crl_dir = (char *)
	        scconf_get_str(pkcs11_mblk,"crl_dir",configuration.policy.crl_dir);
	    configuration.policy.nss_dir = (char *)
	        scconf_get_str(pkcs11_mblk,"nss_dir",configuration.policy.nss_dir);
		configuration.slot_description = (char *)
			scconf_get_str(pkcs11_mblk,"slot_description",configuration.slot_description);

	    configuration.slot_num =
	        scconf_get_int(pkcs11_mblk,"slot_num",configuration.slot_num);

	    if (configuration.slot_description != NULL && configuration.slot_num != -1) {
		DBG1("Can not specify both slot_description and slot_num in file %s",configuration.config_file);
	            return;
	    }

	    if (configuration.slot_description == NULL && configuration.slot_num == -1) {
		DBG1("Neither slot_description nor slot_num found in file %s",configuration.config_file);
	            return;
	    }

	    configuration.support_threads =
	        scconf_get_bool(pkcs11_mblk,"support_threads",configuration.support_threads);
	    policy_list= scconf_find_list(pkcs11_mblk,"cert_policy");
	    while(policy_list) {
	        if ( !strcmp(policy_list->data,"none") ) {
			configuration.policy.crl_policy=CRLP_NONE;
			configuration.policy.ocsp_policy=OCSP_NONE;
			configuration.policy.ca_policy=0;
			configuration.policy.signature_policy=0;
			break;
		} else if ( !strcmp(policy_list->data,"crl_auto") ) {
			configuration.policy.crl_policy=CRLP_AUTO;
		} else if ( !strcmp(policy_list->data,"crl_online") ) {
			configuration.policy.crl_policy=CRLP_ONLINE;
		} else if ( !strcmp(policy_list->data,"crl_offline") ) {
			configuration.policy.crl_policy=CRLP_OFFLINE;
		} else if ( !strcmp(policy_list->data,"ocsp_on") ) {
			configuration.policy.ocsp_policy=OCSP_ON;
		} else if ( !strcmp(policy_list->data,"ca") ) {
			configuration.policy.ca_policy=1;
		} else if ( !strcmp(policy_list->data,"signature") ) {
			configuration.policy.signature_policy=1;
		} else {
                   DBG1("Invalid CRL policy: %s",policy_list->data);
	        }
		policy_list= policy_list->next;
	    }

		configuration.token_type = (char *)
			scconf_get_str(pkcs11_mblk,"token_type",configuration.token_type);
	}
	screen_saver_list = scconf_find_list(root,"screen_savers");
	if (screen_saver_list) {
	   int count,i;
	   for (count=0, tmp=screen_saver_list; tmp ; tmp=tmp->next, count++);

	   configuration.screen_savers = malloc((count+1)*sizeof(char *));
	   for (i=0, tmp=screen_saver_list; tmp; tmp=tmp->next, i++) {
		configuration.screen_savers[i] = (char *)tmp->data;
	   }
	   configuration.screen_savers[count] = 0;
        }
	/* now obtain and initialize mapper list */
	mapper_list = scconf_find_list(root,"use_mappers");
	if (!mapper_list) {
           DBG1("No mappers specified in config: %s",configuration.config_file);
	   return;
	}
	/* load_mappers(ctx); */

    /* Load promt strings */
    parse_prompts(root);

	/* that's all folks: return */
	return;
}

/*
* values are taken in this order (low to high precedence):
* 1- default values
* 2- configuration file
* 3- commandline arguments options
*/
struct configuration_st *pk_configure( int argc, const char **argv ) {
	init_configuration();
	int i;
	/* try to find a configuration file entry */
	for (i = 0; i < argc; i++) {
	    if (strstr(argv[i],"config_file=") ) {
		configuration.config_file=1+strchr(argv[i],'=');
		break;
	    }
    	}
	DBG1("Using config file %s",configuration.config_file);
	/* parse configuration file */
	parse_config_file();
#ifdef DEBUG_CONFIG
	display_config();
#endif
	/* finally parse provided arguments */
	/* dont skip argv[0] */
	for (i = 0; i < argc; i++) {
	   if (strcmp("nullok", argv[i]) == 0) {
		configuration.nullok = 1;
		continue;
	   }
    	   if (strcmp("try_first_pass", argv[i]) == 0) {
      		configuration.try_first_pass = 1;
		continue;
	   }
    	   if (strcmp("use_first_pass", argv[i]) == 0) {
      		configuration.use_first_pass = 1;
		continue;
	   }
    	   if (strcmp("wait_for_card", argv[i]) == 0) {
      		configuration.wait_for_card = 1;
		continue;
	   }
    	   if (strcmp("dont_wait_for_card", argv[i]) == 0) {
      		configuration.wait_for_card = 0;
		continue;
	   }
    	   if (strcmp("debug", argv[i]) == 0) {
      		configuration.debug = 1;
		set_debug_level(1);
		continue;
	   }
    	   if (strcmp("nodebug", argv[i]) == 0) {
      		configuration.debug = 0;
		if (configuration.quiet)
		    set_debug_level(-2);
		else
		    set_debug_level(0);
		continue;
	   }
	   if (strcmp("quiet", argv[i]) == 0) {
		configuration.quiet = 1;
		set_debug_level(-2);
		continue;
	   }
	   if (strstr(argv[i],"pkcs11_module=") ) {
		configuration.pkcs11_module = argv[i] + sizeof("pkcs11_module=")-1;
		continue;
	   }
	   if (strstr(argv[i],"slot_description=") ) {
		configuration.slot_description = argv[i] + sizeof("slot_description=")-1;
		continue;
	   }

	   if (strstr(argv[i],"slot_num=") ) {
		sscanf(argv[i],"slot_num=%d",&configuration.slot_num);
		continue;
	   }

	   if (strstr(argv[i],"ca_dir=") ) {
		configuration.policy.ca_dir = argv[i] + sizeof("ca_dir=")-1;
		continue;
	   }
	   if (strstr(argv[i],"crl_dir=") ) {
		configuration.policy.crl_dir = argv[i] + sizeof("crl_dir=")-1;
		continue;
	   }
	   if (strstr(argv[i],"nss_dir=") ) {
		configuration.policy.nss_dir = argv[i] + sizeof("nss_dir=")-1;
		continue;
	   }
	   if (strstr(argv[i],"cert_policy=") ) {
		if (strstr(argv[i],"none")) {
			configuration.policy.crl_policy=CRLP_NONE;
			configuration.policy.ca_policy=0;
			configuration.policy.signature_policy=0;
			configuration.policy.ocsp_policy=OCSP_NONE;
		}
		if (strstr(argv[i],"crl_online")) {
			configuration.policy.crl_policy=CRLP_ONLINE;
		}
		if (strstr(argv[i],"crl_offline")) {
			configuration.policy.crl_policy=CRLP_OFFLINE;
		}
		if (strstr(argv[i],"crl_auto")) {
			configuration.policy.crl_policy=CRLP_AUTO;
		}
		if ( strstr(argv[i],"ocsp_on") ) {
			configuration.policy.ocsp_policy=OCSP_ON;
		}
		if (strstr(argv[i],"ca")) {
			configuration.policy.ca_policy=1;
		}
		if (strstr(argv[i],"signature")) {
			configuration.policy.signature_policy=1;
		}
		continue;
	   }

	   if (strstr(argv[i],"token_type=") ) {
		configuration.token_type = argv[i] + sizeof("token_type=")-1;
		continue;
	   }

	   if (strstr(argv[i],"config_file=") ) {
		/* already parsed, skip */
		continue;
	   }
    	   /* if argument is not recognised, log error message */
           syslog(LOG_ERR, "argument %s is not supported by this module", argv[i]);
           DBG1("argument %s is not supported by this module", argv[i]);
	}
#ifdef DEBUG_CONFIG
	display_config();
#endif

	return &configuration;
}
