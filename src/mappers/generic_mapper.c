/*
 * PAM-PKCS11 generic mapper skeleton
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
 * pam-pkcs11 is copyright (C) 2003-2004 of Mario Strasser <mast@gmx.net>
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * $Id$
 */

#define __GENERIC_MAPPER_C_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*#include <openssl/evp.h> */
#include "../common/cert_st.h"
#include "../scconf/scconf.h"
#include "../common/debug.h"
#include "../common/error.h"
#include "../common/strings.h"
#include "../common/cert_info.h"
#include "../common/base64.h"
#include <openssl/sha.h>
#include "mapper.h"
#include "generic_mapper.h"

/*
* Skeleton for mapper modules
*/

static const char *mapfile = "none";
static int usepwent = 0;
static int ignorecase = 0;
static int id_type = CERT_CN;
static const char *algorithm = ALGORITHM_NULL;
static int debug = 0;
static const char *prefix;
static const char *postfix;
static int scramble = 0;

#define MAX_ENTRY_LEN 256
static int maxlen = MAX_ENTRY_LEN;

static const char *user_desc = NULL;
static const char *desc_mapfile = NULL;

static char *scramble_entry(const char* entry);
static void parse_search_item(const char *item, int *id_type, const char **algo);

static char **generic_mapper_find_entries(X509 *x509, void *context) {
    if (!x509) {
        DBG("NULL certificate provided");
        return NULL;
    }

    char **entries = cert_info(x509, id_type, algorithm);
    if (!entries) {
        return NULL;
    }

    char *entry; int n;
    char *entrybuf;
    for (n=0, entry=entries[n]; entry; entry=entries[++n]) {
        if (scramble) {
            entries[n] = scramble_entry(entry);
            // FIXME: free(entry) ?
            entry = entries[n];
        }
        if ((prefix || postfix) && NULL != entry)  {
            entrybuf = malloc(MAX_ENTRY_LEN);
            if (!entrybuf) {
                DBG("Unable to allocate entry buffer");
                entries[n] = NULL;
            } else {
                snprintf(entrybuf, MAX_ENTRY_LEN, "%s%s%s",
                         prefix, entry, postfix);
                entries[n] = entrybuf;
                // FIXME: free(entry) ?
                entry = entries[n];
            }
        }
    }
    
	return entries;
}

#define SHA1_LENGTH 20

static char *scramble_entry(const char* entry) {
    unsigned char hash[SHA1_LENGTH];
    size_t entrysize = (4 * ((sizeof(hash) + 2) / 3)) + 1;
    char *entrybuf;
    SHA1(entry, strlen(entry), hash);

    entrybuf = malloc(entrysize);
    if (!entrybuf) {
        DBG("Unable to allocate entry buffer");
        return NULL;
    }

    size_t outlen = entrysize;
    if ( 0 != base64_encode(hash, sizeof(hash), entrybuf, &outlen) ) {
        DBG("Unexpected error: unable to BASE64-encode the entry");
        return NULL;
    }
    
    int i;
    for (i = 0; i < outlen; i++) {
        if (entrybuf[i] >= 'A' && entrybuf[i] <= 'Z') {
            entrybuf[i] = entrybuf[i] + 'a' - 'A';
        } else {
            switch (entrybuf[i]) {
            case '+':
            case '/':
            case '=':
                entrybuf[i] = 'o';
            }
        }
    }

    if (outlen > maxlen) {
        entrybuf[maxlen] = '\0';
    }

    return entrybuf;
}

static char **get_mapped_entries(char **entries, const char *mapfile, int usepwent) {
	int match = 0;
	char *entry;
	int n=0;
	char *res=NULL;
	/* if mapfile is provided, map entries according it */
	if ( !mapfile || strlen(mapfile) == 0 || !strcmp(mapfile,"none") ) {
	    DBG("Use map file is disabled");
	} else {
	    DBG1("Using map file '%s'", mapfile);
	    for(n=0, entry=entries[n]; entry; entry=entries[++n]) {
		res = mapfile_find(mapfile,entry,ignorecase,&match);
		if (res) entries[n]=res;
	    }
	}
	/* if NSS is set, re-map entries against it */
	if ( usepwent == 0 ) {
	    DBG("Use Naming Services is disabled");
	} else {
	    res=NULL;
	    DBG("Using Naming Services");
	    for(n=0,entry=entries[n];entry;entry=entries[++n]) {
		res = search_pw_entry(entry,ignorecase);
		if (res) entries[n]=res;
	    }
	}
	return entries;
}

static char *generic_mapper_find_entry(char **entries, const char *themapfile, int usepwent) {
	int n;

    /* do file and pwent mapping */
    entries = get_mapped_entries(entries, themapfile, usepwent);

	/* and now return first nonzero item */
	for (n = 0; n < CERT_INFO_SIZE; n++) {
	    char *str = entries[n];
	    if (str && !is_empty_str(str) ) {
	    	return str;
	    }
	}

	/* arriving here means no map found */
	return NULL;
}

static char *generic_mapper_find_user(X509 *x509, void *context, int *match) {
    if (!x509) {
        DBG("NULL certificate provided");
        return NULL;
    }

    char **entries = generic_mapper_find_entries(x509, context);
	if (!entries) {
		DBG("Cannot find any entries in certificate");
		return NULL;
	}

    char *str = generic_mapper_find_entry(entries, mapfile, usepwent);
    if (str) {
        *match = 1;
        return clone_str(str);
    }

    return NULL;
}

static char *generic_mapper_find_description(X509 *x509, void *context) {
    if (!x509) {
        DBG("NULL certificate provided");
        return NULL;
    }

    if (!user_desc) return NULL;

    int item_id = CERT_CN;
    const char *algo = ALGORITHM_NULL;
    parse_search_item(user_desc, &item_id, &algo);

    char **entries = cert_info(x509, item_id, algo);
	if (!entries) {
		DBG("Cannot find any entries in certificate");
		return NULL;
	}

    char *str = generic_mapper_find_entry(entries, desc_mapfile, 0);
    if (str) {
        return clone_str(str);
    }

    return NULL;
}

static int generic_mapper_match_user(X509 *x509, const char *login, void *context) {
	char **entries;
	int n;
        if (!x509) {
                DBG("NULL certificate provided");
                return 0;
        }
	if (!login || is_empty_str(login) ) {
		DBG("NULL login provided");
		return 0;
	}
	entries= generic_mapper_find_entries(x509,context);
	if (!entries) {
		DBG("Cannot find any entries in certificate");
		return 0;
	}
	/* do file and pwent mapping */
	entries = get_mapped_entries(entries, mapfile, usepwent);
	/* and now try to match entries with provided login  */
	for (n=0;n<CERT_INFO_SIZE;n++) {
	    char *str=entries[n];
	    if (!str || is_empty_str(str) ) continue;
	    DBG2("Trying to match generic_mapped entry '%s' with login '%s'",str,login);
	    if (ignorecase) {
		if (! strcasecmp(str,login) ) return 1;
	    } else {
		if (! strcmp(str,login) ) return 1;
	    }
	}
	/* arriving here means no map found */
	DBG("End of list reached without login match");
	return 0;
}

_DEFAULT_MAPPER_END

static mapper_module * init_mapper_st(scconf_block *blk, const char *name) {
	mapper_module *pt= malloc(sizeof(mapper_module));
	if (!pt) return NULL;
	pt->name = name;
	pt->block = blk;
	pt->context = NULL;
	pt->entries = generic_mapper_find_entries;
	pt->finder = generic_mapper_find_user;
    pt->describer = generic_mapper_find_description;
	pt->matcher = generic_mapper_match_user;
	pt->deinit = mapper_module_end;
	return pt;
}

static void parse_search_item(const char *item, int *id_type, const char **algo) {
    if (!strcasecmp(item,"cn"))           *id_type=CERT_CN;
    else if (!strcasecmp(item,"subject")) *id_type=CERT_SUBJECT;
    else if (!strcasecmp(item,"kpn") )    *id_type=CERT_KPN;
    else if (!strcasecmp(item,"email") )  *id_type=CERT_EMAIL;
    else if (!strcasecmp(item,"upn") )    *id_type=CERT_UPN;
	else if (!strcasecmp(item,"uid") )    *id_type=CERT_UID;
	else if (!strcasecmp(item,"serial") ) *id_type=CERT_SERIAL;
	else if (strlen(item) > 2 && item[0] >= '0' && item[0] < '3' && item[1] == '.') {
        *id_type = CERT_OID;
        *algo = item;
    } else {
	    DBG1("Invalid certificate item to search '%s'; using 'cn'",item);
	}
}

/**
* Initialize module
* returns 1 on success, 0 on error
*/
#ifndef GENERIC_MAPPER_STATIC
mapper_module * mapper_module_init(scconf_block *blk,const char *name) {
#else
mapper_module * generic_mapper_module_init(scconf_block *blk,const char *name) {
#endif
	mapper_module *pt;
	const char *item="cn";
	if (blk) {
	debug = scconf_get_bool( blk,"debug",0);
	ignorecase = scconf_get_bool( blk,"ignorecase",0);
	usepwent = scconf_get_bool( blk,"use_getpwent",0);
	mapfile= scconf_get_str(blk,"mapfile",mapfile);
	item = scconf_get_str(blk,"cert_item","cn");
    prefix = scconf_get_str(blk,"prefix", "");
    postfix = scconf_get_str(blk,"postfix", "");
    scramble = scconf_get_bool(blk,"scramble", 0);
    maxlen = scconf_get_int(blk,"maxlen", MAX_ENTRY_LEN);
    user_desc = scconf_get_str(blk,"user_desc", NULL);
    desc_mapfile = scconf_get_str(blk,"desc_mapfile", NULL);
	} else {
		/* should not occurs, but... */
		DBG1("No block declaration for mapper '%s'",name);
	}
	set_debug_level(debug);
    parse_search_item(item, &id_type, &algorithm);
	pt = init_mapper_st(blk,name);
	if (pt) DBG5("Generic mapper started. debug: %d, mapfile: '%s', ignorecase: %d usepwent: %d idType: '%d'",debug,mapfile,ignorecase,usepwent,id_type);
	else DBG("Generic mapper initialization failed");
	return pt;
}

