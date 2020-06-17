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

/*
* configuration related functions
*/
#ifndef _PAM_CONFIG_H_
#define _PAM_CONFIG_H_

#include "../scconf/scconf.h"
#include "../common/cert_vfy.h"

#ifdef ENABLE_PWQUALITY
#include <pwquality.h>
#endif

struct prompts_st {
    const char *start_auth;
    const char *insert_named;
    const char *insert;
    const char *no_card;
    const char *no_card_err;
    const char *found;
    const char *login_failed;
    const char *welcome;
    const char *welcome_locked;
    const char *wrong_pin;
    const char *wrong_pin_locked;
    const char *no_cert;
    const char *cert_verif;
    const char *cert_expired;
    const char *cert_not_yet;
    const char *cert_inv_sig;
    const char *cert_inv;
    const char *no_user_match;
    const char *no_cert_match;
    const char *pin_prompt;
    const char *pin_read_err;
    const char *empty_pin_err;
    const char *enter_pin_pinpad;
    const char *checking_sig;
    const char *sig_failed;
    const char *sig_verif_failed;
    const char *enter_old_pin;
    const char *enter_so_pin;
    const char *enter_new_pin;
    const char *confirm_pin;
    const char *confirm_pin_mismatch;
    const char *change_on_pinpad;
    const char *pin_change_err;
    const char *pin_change_err_locked;
    const char *so_pin_change_err;
    const char *so_pin_change_err_locked;
    const char *pin_locked;
    const char *pin_final_try;
    const char *were_incorrect;
    const char *pin_n_only;
    const char *pin_1_only;
    const char *pin_n_left;
    const char *pin_1_left;
    const char *pin_to_be_changed;
    const char *pin_expired;
    const char *changing_user_pin;
    const char *user_pin_reset;
    const char *changing_user_pin_locked;
#ifdef ENABLE_PWQUALITY
    const char *pwquality_err;
#endif
};

struct configuration_st {
	const char *config_file;
	scconf_context *ctx;
	int debug;
	int nullok;
	int try_first_pass;
	int use_first_pass;
	int use_authok;
	int card_only;
	int wait_for_card;
	const char *pkcs11_module;
	const char *pkcs11_modulepath;
	const char **screen_savers;
	const char *slot_description;
	int slot_num;
	int support_threads;
	cert_policy policy;
	const char *token_type;
	const char *username; /* provided user name */
	int quiet;
    int verbose;
	int err_display_time;
    int pin_count_low;
    int reset_pin_low;
    int reset_pin_locked;
    int force_pin_change;
    const char *default_username;
	int ask_pin;
    int change_pin_early;

#ifdef ENABLE_PWQUALITY
    const char *pwquality_config;
    pwquality_settings_t *pwq;
#endif

    struct prompts_st prompts;
};

struct configuration_st *pk_configure( const char *service,
                                       int argc, const char **argv );

#endif
