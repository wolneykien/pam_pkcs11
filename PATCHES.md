# ALT patches

The patch layout:

* `ignore-no-card`
* `systemd`
* `syslog`
* `eventmgr-card-error`
* `oid-mapper`
* `userdesc`
* `default-user`
* `setpin`
  * `pin-checks`
    * `isbc`
    * `pwquality`
* `snprintf`
* `ask-pin`
  * `welcome-user`
* `opensslconf`
* `global-ca`
* `blacklist`
* `prompts`
* `gost`
* `query-config`
* `use-openssl`
* `scconf`
* `opensslfix`
* `fixes`
* `ru`


## `ignore-no-card`

Don't stuck if `wait_for_card=false` and ignore the token not found
error when the auth isn't restricted to card only (either by option or
by `PKCS11_LOGIN_TOKEN_NAME` environment variable).

It allows to pass to a next module in the PAM stack if the auth isn't
restricted to card only.

The meaning of `card_only` flags changes to the following:
restrict the authentication to token _only if_ the user has
already authenticated by a token. Thus, in order to restrict the
authentication for _new logins_ to card only the `wait_for_card` flag
should be used _along_ with `card_only` flag.

**TODO**:
* Update the `docs/` and `pam.d/login` example!


## `systemd`

A simple patch adding the `pkcs11-eventmgr.service` unit.


## `syslog`

Adds token label and serial to the syslog messages.
Also, introduces `pam_syslog()` and `pam_vsyslog()` wrappers for
Open PAM.


## `eventmgr-card-error`

Ignore the first event after `CARD_ERROR`. Also, use the `CARD_ERROR`
as initial state value to re-implement a skip on the frist pass.

Also, added `waitevent` command-line option to use
`C_WaitForSlotEvent()`.


## `oid-mapper`

Allow to use any OID value _number_ (e.g. "1.2.643.100.3") with the
generic mapper.

The following new options are also supported:

* `scramble` (`true | false`) --- hash the extracted value with SHA1
  hash;
* `maxlen` --- limit the length of the _hashed_ value (chars);
* `prefix` --- add prefix to the extracted value;
* `postfix` --- add postfix to the extracted value.


## `userdesc`

Adds `find_user_desc()` and `match_user_desc()` functions allowing to
get a user description data along with the login.


## `default-user`

The Patch adds `default_username` configuration parameter providing
a default value for `PAM_USER`. The module doesn't prompt for a user
name if default is configured.


## `setpin`

This implements the `pam_sm_chauthtok()` PAM function using the
`C_SetPin()` PKCS#11 call. Some refactoring of the password asking and
password checking code is also here.


## `pin-checks`

Is related to the `setpin` patch and adds a special **lowlevel**
interface to check the number of attemps left to enter an
invalid PIN. The configuration parameter `pin_count_low` is used to
set up when to display the warning message.

The other `force_pin_change` configuration flag controls whether to
switch the module into PIN-change mode after login when it's time to
change the user's PIN (with the user of `CKF_USER_PIN_TO_BE_CHANGED`
PKCS#11 flag).


## `pwquality`

Uses the `libpwquality` library to check the PIN-code streingth.


## `snprintf`

Some `sprintf()` -> `snprintf()` replacements.


## `ask-pin`

New contifuration option `ask_pin_later`. With `ask_pin_later`
the token is inspected before login as some tokens allow to
read public data before login.

The PIN is asked directly before PIN verification.


## `welcome-user`

Welcome the user by a description from their certificate.
Depends on `ask-pin` and `userdesc` patches.


## `opensslconf`

Setup OpenSSL with `CONFDIR "/openssl.cnf"` if that file exists.


## `global-ca`

Adds `global_ca` certificate policy to check the system-wide CA
certificate list.


## `blacklist`

Adds slot blaklisting support to `pkcs11_lib` with
`set_slot_blacklist()` interface function.

**TODO:** Add it to the header!


## `prompts`

Allows the user prompts and messages to be configured from the
configuration file. Also adds the `verbose` configuration option and
makes `quite` to affect only the syslog output.


## `gost`

Adds support for some GOST ciphers.


## `isbc`

Implements lowlevel functions defined in `pin-checks` for the "ESMART"
token.


## `query-config`

Added a tool to qeury the `pam_pkcs11.conf` configuration file values.


## `use-openssl`

Remove `pkcs11_make_hash_link`. Our users can run `c_rehash` instead.


## `scconf`

Some scconf improvements.


## `opensslfix`

Fixes to deal with old and new OpenSSL versions, i.e.:

    #if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ...
    #else
    ...
    #endif


## `fixes`

Various small fixes including type casts and printf() formats.


## `ru`

Updated Russian translations.
