# ALT patches

The patch layout:

* `ignore-no-card`
* `systemd`
* `eventmgr-card-error`
* `oid-mapper`
* `userdesc`
* `setpin`
  * `pin-checks`
    * `isbc`
    * `pwquality`
* `snprintf`
* `ask-pin`
* `opensslconf`
* `global-ca`
* `blacklist`
* `prompts`
* `gost`


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
* pick a72a9f8 for `ask-pin` for merge.

## `systemd`

A simple patch adding the `pkcs11-eventmgr.service` unit.


## `eventmgr-card-error`

Ignore the first event after `CARD_ERROR`. Also, use the `CARD_ERROR`
as initial state value to re-implement a skip on the frist pass.


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

New contifuration option `ask_pin`. Without `ask_pin` the
`pkcs11_login()` is called with _empty password_ (PIN).

With `ask_pin` (the default) the PIN is asked _after_ the certificate
list is obtained from the token.


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