# Behaviour the cove fork promises to cove

This file lists the fork behaviour cove depends on. A change here is a change
to a contract: tell cove before it lands.

## SSO failure: `login_error` and `retry_after` on the caller's `next`

When an SSO login started with a `next` query parameter, a failure at the SSO
return (`/@warpgate/api/sso/return`) sends the browser back to that `next`
instead of to the `/@warpgate` login page.

Only a safe `next` qualifies: a site-relative path starting with a single `/`
(not `//`, not `/\`, not an absolute URL), and still one once
percent-decoded, however many times it was encoded. A `next` is refused if
any layer of it holds a backslash, an encoded `/` or `\` (`%2f`, `%5c`, in
either case), a control character or an `@`, the one `@` allowed being the
leading one of Warpgate's own `/@warpgate` path. The redirect goes to the
origin the SSO return URL named, so `next` can never carry the browser
off-site. The same check applies to the `next` of the sign-in handoff's
begin route (see "Starting a sign-in from a target's host").

Every SSO entry (`/sso/auto-start` and `/sso/providers/{name}/start`) also
takes an absolute `next`: an `https://` URL whose host is either the
control-plane host (`http.external_host` when set, else `external_host`),
matched exactly, or the cookie domain (`external_host`) or a whole-label
subdomain of it (`a.example.com` for `example.com`, never `badexample.com`).
The control-plane host's port must be the one written in `http.external_host`
if it has one, else `http.external_port`, else the listen port (8888 by
default). The cookie domain and its subdomains take `http.external_port`, else
the listen port; a port written in `external_host` does not count. An `https`
URL with no port means 443. Plain `http`, user info, `//host`, a
trailing dot or empty label, an IP address, a backslash or whitespace, and any
other host or port are refused. `/sso/auto-start` drops a refused `next` at
once; the SSO return checks it again, and a refused one lands the browser on
the login page. An allowed absolute `next` is followed in its canonical form
(lower-case host, punycode).

A failure of the sign-in does not carry `login_error` or `retry_after` to an
absolute `next`: those go only to a relative `next`. After a failure with an
absolute `next` the browser goes to `/@warpgate?login_error=...`, or gets an
error response where the code could not be verified.

### Parameters

| Parameter     | When                         | Value                                   |
|---------------|------------------------------|-----------------------------------------|
| `login_error` | every SSO failure            | one of the four codes below             |
| `retry_after` | only with `ip_blocked`       | integer seconds until the IP is unblocked |

`retry_after` is the time left on the client IP's login-protection block,
rounded down to whole seconds, and `0` if the block has just expired. It is
never sent with any other code.

### Codes

The set is exactly these four. A new code is a new contract.

| Code               | Meaning                                                                 |
|--------------------|-------------------------------------------------------------------------|
| `ip_blocked`       | Login protection rejected the credential because the client IP is blocked. |
| `sso_failed`       | Any other SSO validation failure: bad or missing state or code, unverified e-mail, a rejected credential. A locked account is reported as `sso_failed`, so an unproven caller learns nothing about lock status. |
| `no_matching_user` | SSO succeeded but no Warpgate user matches the identity.                |
| `access_denied`    | The user exists but is not allowed in (for example the user's allowed IP range excludes the client). |

Warpgate logs the real underlying reason server-side.

### Rules

- Any `login_error` or `retry_after` already present in `next` is removed
  before the new ones are appended, so the caller cannot forge either.
- The parameters are appended with `&` if `next` already has a query, else `?`,
  and always before a `#fragment`.
- Without a safe `next` (none given, or an unsafe one) nothing changes: the
  browser goes to the `/@warpgate` login page with a free-text `login_error`,
  and no `retry_after`.
- A failure before the SSO handshake is found (no `state`, no `code`, no active
  SSO process) has no `next` to return to and takes the fallback.
- An existing Warpgate session cookie may survive a failed retry. Treat a
  request that arrives with `login_error` as a failure whatever the session says.

### A fifth outcome: 403 for a ticket session

A browser session opened with a ticket never signs in, by any route, so it
never becomes a user session. Each of these answers `403 Forbidden` with a
plain-text body (sign out, then sign in with single sign-on), and stores and
changes nothing:

- the SSO start: `/@warpgate/api/sso/auto-start` (with or without `force`)
  and `/@warpgate/api/sso/providers/<name>/start`, and the login page's own
  auto-redirect;
- the SSO return (`/@warpgate/api/sso/return`), checked before the handshake
  is looked up, so the session stays a ticket session;
- the completion of any other sign-in: password, OTP, passkey.

This is not a `login_error` code and is never sent to `next`: the browser
gets the 403 itself. The four codes above are unchanged.

## Always start SSO: `/sso/auto-start?force=1`

`GET /@warpgate/api/sso/auto-start?force=1` starts SSO even when the browser
is already signed in, and whether or not `sso_auto_redirect` is on.

| Query      | Meaning                                                              |
|------------|----------------------------------------------------------------------|
| `force`    | Only the exact value `1` turns this on. Anything else: today's behaviour. |
| `provider` | Optional, used only with `force=1`: the SSO provider's name, compared exactly. |
| `next`     | Where the browser returns after the sign-in; the safe-redirect rule above applies, an unsafe one is dropped. |
| `login`    | `login=password` still wins: the login page with the password form, no SSO. |

With `force=1`:

- a configured `provider` is started (302 to the identity provider);
- with no `provider` and exactly one configured, that one is started;
- an unknown `provider`, or none named among several, gets the login page
  (302 to `/@warpgate#/login`, with `next`), never an error;
- a ticket session gets 403 (above);
- a return with no fresh stamp is refused: Warpgate refuses a forced return
  that yields no new stamp, with `login_error=sso_failed` on the `next` (see
  "What `last_sso_at` means"), so a `force=1` that comes back succeeds only
  with a fresh stamp;
- the authorize request carries `prompt=login` (except where the provider
  type rejects it; see the per-provider paragraph below) and `max_age=0`, so
  an identity provider that honours them asks the user to sign in again
  rather than resume its own session. Every other SSO start (the login page's
  provider buttons, the auto-redirect) never sends `prompt`, and sends
  `max_age` in seconds when HTTP step-up is configured, nothing otherwise. That `max_age` is
  `step_up_interval.http` less a margin of a quarter of it (at most one hour),
  never below zero, so a login the provider takes as recent is stamped fresh
  for at least the margin after the return, and never outlasts the interval.
  The return applies the same value: a stamp not newer than now less that
  `max_age` does not count as recent;
- every `force=1` start and every start while HTTP step-up is configured also
  sends the OpenID Connect `claims` parameter
  `{"id_token":{"auth_time":{"essential":true}}}`, for providers that include
  `auth_time` only when asked. SSH-only step-up sends neither `claims` nor
  `max_age`.

Per provider type:

- **Google** rejects `prompt=login`, so a `google` provider gets `max_age` and
  the `claims` parameter without `prompt`. Google does not support Google
  Account reauth requests
  (developers.google.com/identity/siwg/security-bundle); `max_age` is not
  among Google's documented authorize parameters, and `prompt` allows only
  `none`, `consent` and `select_account`
  (developers.google.com/identity/openid-connect/reference). Google returns
  `auth_time` only when the Google app is In production, Verified, and has
  "Session age claims" turned on (Settings > Advanced Settings), in addition
  to the `claims` request. What users see: on Google, `force=1` essentially
  never yields a fresh stamp (a `force=1` return stamps only from an
  `auth_time` not older than the handshake, see below), so cove refuses a
  request that needs a fresh sign-in unless the user actually signed in at
  Google during that round (no Google session, for example after signing out
  of Google) and the app reports `auth_time`. Under HTTP step-up, where Google
  does report `auth_time`, a user whose Google session is older than the
  `max_age` and whose Warpgate session holds no recent stamp gets `sso_failed`
  on every plain start until they sign out of Google; retrying does not help.
  Where Google reports no `auth_time` at all (the default for a Google app),
  no Google sign-in ever stamps. Under HTTP step-up it succeeds only on a
  session that already holds a recent stamp for the same user, which only a
  return that carried `auth_time` (another provider) can have written; with
  Google as the only provider, nobody can sign in, and signing out of Google
  does not help.
  Do not turn on HTTP step-up when Google is the only SSO provider: Google
  rejects `prompt=login`, so it gets no `prompt`, and it does not document
  `max_age`, so it cannot be made to ask the user to sign in again.
- **Apple** gets `max_age` and `claims` on every HTTP step-up start, and
  `prompt=login` plus `max_age=0` on `force=1`. Whether Apple honours them is
  unverified.
- **Entra** (`azure`) and `custom` providers are treated the same way: `max_age`
  and `claims` on every HTTP step-up start, and `prompt=login` plus `max_age=0`
  on `force=1`. Whether they honour them, and whether they report `auth_time`,
  is the provider's behaviour.

Confirm each provider (Google, Apple, Entra and every `custom` one) before
turning HTTP step-up on. Check a plain step-up start as well as `force=1`:
every start under HTTP step-up sends `claims` and `max_age`, so a provider that
rejects `claims` would break every sign-in under step-up, not only the
`force=1` ones.

The return stamps the session's `last_sso_at`. A password, OTP or passkey
sign-in never does, so `?login=password` never makes a session fresh.

### What `last_sso_at` means

`last_sso_at` means "the identity provider says the user last signed in at
time t". Warpgate stamps it, at an SSO return, from the `auth_time` claim of
the ID token that return exchanged, never from its own clock
(`warpgate-core/src/auth/step_up.rs`, `sso_stamp`). That token is bound to the
handshake by its single-use `state` and its `nonce`, so a token from another
handshake is refused and never stamps. The stamp is written only when:

- `auth_time` is present, and at most 120 s ahead of Warpgate's clock (a
  later one is ignored; one within the 120 s is clamped to now);
- for a `force=1` handshake the window is tighter: `auth_time` is within 30 s
  of the handshake's start (an identity provider that ignored `prompt=login`
  and sent an old sign-in time does not advance the stamp) and at most 30 s
  ahead of Warpgate's clock, and it is stamped exactly as given, never
  clamped to now;
- it is later than the stamp the session already has, so a stamp never moves
  backwards.

Otherwise a plain return still signs the user in and leaves the stamp as it
was, with one exception: when HTTP step-up is on and the session would be left
with no recent stamp (newer than now less the `max_age` above), the sign-in is
refused (the `sso_failed` return), before the credential is submitted. A
`force=1` return is stricter, with or without step-up: if it yields no new
stamp (`auth_time` absent, not a number, more than 30 s ahead, more than 30 s
before the handshake began, or not later than the session's existing stamp) the
sign-in is refused the same way and nothing is written. This holds with
step-up off too, so any `force=1` return can fail with `sso_failed`. An
identity provider whose clock is more than 30 s behind Warpgate's reports an
`auth_time` more than 30 s before the handshake began, so every `force=1`
against it fails until the clocks agree. A different user's return never
inherits the session's stamp.

Known limit: a sign-in whose age is exactly the `max_age` can be refused once
and pass on retry. The return counts a stamp as recent only when it is strictly
newer than now less `max_age` (`is_recent_enough`), while an identity provider
treats a login exactly that old as still recent and resumes its session. The
retry is older than `max_age`, so the provider asks for a new sign-in, which
passes.

Known limit: an identity provider that answers `prompt=login` / `max_age=0`
from its own session, without asking the user to sign in again, returns the
same `auth_time` as before. That is not later than the session's stamp, so a
`force=1` step-up fails with the no-recent-authentication refusal
(`sso_failed`). The user must sign in again at the identity provider (sign out
there, or end its session) and retry.

An identity provider that does not return `auth_time` never stamps; with HTTP
step-up on, its users cannot sign in. Confirm that the provider returns
`auth_time` after `prompt=login` before relying on it.

Another site can still navigate the browser through `/sso/auto-start?force=1`
(an unauthenticated GET; the session cookie is `SameSite=Lax`, so it is sent
on a top-level navigation). `force=1` asks the provider to make the user sign
in again, so no stamp is refreshed without a fresh sign-in, but a user who is
shown that prompt may complete it. `last_sso_at` is still not an
intent token and not a CSRF token: a verifier (cove) must keep its own CSRF
check and must not read a recent `last_sso_at` as proof that the user chose
this action.

Cove's side: for one request that needs a fresh sign-in, start one `force=1`
round. If the statement from the session it returns to does not carry a
`last_sso_at` of at least cove's own request start less 30 s, refuse the
request; do not start a second round. The signed statement
carries no `auth_time` of its own.

## Signed session statement: `x-warpgate-session-freshness`

An HTTP target with `signed_statement` on (a boolean in the target's HTTP
options, off by default, settable through the admin API only) receives, on
every proxied request from a browser session that signed in as a user, one
header:

    x-warpgate-session-freshness: v1.<kid>.<payload>.<sig>

It is set last, after the target's configured headers and URL credentials,
with one copy upstream, on plain and WebSocket requests. A request with no
signed-in session (and the public-target bypass) carries none; so does a
Warpgate with no statement key. The admin API refuses a configured header
whose name starts with `x-warpgate-` (case-insensitive).

A session started with a ticket carries none, even when it was a user session
before: a ticket for the same user, presented on a user session, makes it a
ticket session, and its `last_sso_at` is cleared. A target bound to a host
(`external_host` non-empty) outside Warpgate's own external host and its
subdomains (the session cookie domain) carries none either, for anyone; one
bound to that host or a subdomain of it is treated like any other target
(whole DNS labels, case-insensitive, one trailing dot and any port ignored).
If Warpgate's own host cannot be determined, a bound host gets none. The statement is
made only while the session's authorization is a user's, so `auth` is always
`user`; the field is kept so a verifier need not guess.

`payload` is base64url (no padding) of JSON with exactly these 11 keys, in this order, each exactly once:
`aud` (target id), `sub` (user id), `name` (username), `auth` (always
`user`), `last_sso_at` (Unix seconds or `null`), `iat`, `exp` (`iat` + 30),
`jti`, `m` (method), `p` (upstream path and query as forwarded), `sh` (session
hash or `null`). Only `last_sso_at` and `sh` may be `null`. A verifier rejects
a payload with a missing key, a repeated key, any other key (so there is no
`tid` and no `auth_time`), or a `jti` that does not decode to exactly 16 bytes.
Check this on the text as received: a JSON parser that keeps the last of two
equal keys hides a repeat.

- `jti` is base64url (no padding) of 16 bytes from the operating system's
  random number generator, new for every statement, inside the signed bytes.
  A receiver keeps a replay cache keyed on `(kid, jti)`, holding each entry
  until `exp` plus any clock leeway the verifier allows (at least the 30
  seconds a statement lives), and refuses a statement it has already seen. The
  cache is shared across verifier replicas: one shared store, not one per
  process.
- `last_sso_at` is the identity provider's sign-in time (the ID token's
  `auth_time`), as in "What `last_sso_at` means" above. No other sign-in time
  is in the statement: there is no `auth_time`.
- `sh` is base64url (no padding) of SHA-256 over the length-prefixed
  `cove-session-hash-v1` and the Warpgate session id in hyphenated lowercase;
  `null` when the browser session has no id.
- `sig` is base64url (no padding) of the 64-byte Ed25519 signature over, for
  each of `cove-session-freshness-v1`, `kid` and the `payload` text exactly as
  sent: a 4-byte big-endian length, then the bytes.
- `kid` is base64url (no padding) of SHA-256 of the raw 32-byte public key.

A verifier checks the version, looks `kid` up among the keys it pinned,
verifies the signature over the bytes it received, then reads the payload,
and checks `aud`, `m`, `p` and `exp` against its own request. A verifier must
check `auth == "user"` before it trusts `last_sso_at`: a statement with any
other `auth` says nothing about a fresh sign-in. Even then `last_sso_at` only
says the identity provider reported the user's last sign-in at that time (see
"What `last_sso_at` means"); it does not show the user's intent, and the verifier's own CSRF check stays.

### Keys

`GET /@warpgate/api/statement-keys` (no authentication; a host bound to a
target answers 404) returns `[{kid, alg: "Ed25519", public_key, signing}]`;
`signing` is true for the one key that signs. The list is empty, and nothing
is signed, when `WARPGATE_ENCRYPTION_KEY` is not set. The private half is
stored encrypted, never shown by any API, UI or log.

Rotation is on the host: `warpgate statement-keys list | add-next | promote
<kid> | retire <kid>`. Publish first: `add-next`, pin the new key in every
verifier, `promote` (the signing key becomes `retiring`), wait at least 5
seconds, then `retire` the old one. Each running node keeps its signing key
cached for up to 5 seconds, so it can still sign with the old key just after
`promote`; `retire` deletes the key at once, and a verifier that has dropped it
refuses those statements. `promote` refuses while a `retiring` key exists;
`retire` refuses the signing key. `retire` does not enforce the 5 second wait
after `promote`: an early `retire` deletes the key while a node may still sign
with it, and those statements fail closed at a verifier that has dropped the
key.

### Shared test vector

Seed: the 32 bytes 0, 1, ..., 31. Session id
`01234567-89ab-cdef-0123-456789abcdef`. Fields: `aud`
`6f1b0c3e-0000-4000-8000-000000000001`, `sub`
`9a7e5b2c-0000-4000-8000-000000000002`, `name` `alice`, `auth` `user`,
`last_sso_at` 1795000000, `iat` 1795000100, `exp` 1795000130, `jti` the 16
bytes `0xA5` (`paWlpaWlpaWlpaWlpaWlpQ`), `m` `POST`, `p`
`/vms/dev/delete?confirm=1`.

- public key: `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`
- `kid`: `Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw`
- `sh`: `csYevRtBmdkph9kYTknQH15jWwvnGD8dkDC7ixc-y2I`
- header value (accept):

```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9jb25maXJtPTEiLCJzaCI6ImNzWWV2UnRCbWRrcGg5a1lUa25RSDE1ald3dm5HRDhka0RDN2l4Yy15MkkifQ.uMiCuNaQvmp4o1EhcG1nAlRZSMB9KWAsVLOf0raV4Ac4rH7g6QCMPxDu84VkRz5SMMAya77y09S5S52ZQZygDw
```

Same fields with `last_sso_at` `null` and `sh` `null` (a password sign-in on a
browser session with no session id); accept:

```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjpudWxsLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9jb25maXJtPTEiLCJzaCI6bnVsbH0.6quPIPTzEvC7xdK8SXvc4vUo1xjOWYShKvJDMs7FyJCOpv4Sttou5oMDodRPqZZ79auxivVlzs8o7FU6ynJuBw
```

Signed with the same key, correct signatures, but refuse each: the payload
breaks the 11-key rule.

- `missing_jti`: no `jti` (10 keys).
```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwibSI6IlBPU1QiLCJwIjoiL3Ztcy9kZXYvZGVsZXRlP2NvbmZpcm09MSIsInNoIjoiY3NZZXZSdEJtZGtwaDlrWVRrblFIMTVqV3d2bkdEOGRrREM3aXhjLXkySSJ9.LlWIYgZU1-DrGdhAGyH2qpBo9KK-TYJLNPiVtLAMlMrL8ilgWVJBHRqZM2bLxwbHzFbzdRCIzpy_EU08NkmrDA
```
- `duplicate_m`: `m` twice (12 entries).
```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9jb25maXJtPTEiLCJtIjoiR0VUIiwic2giOiJjc1lldlJ0Qm1ka3BoOWtZVGtuUUgxNWpXd3ZuR0Q4ZGtEQzdpeGMteTJJIn0.FTUDKcyMFenG1CGdLFDKDVuIfNSE8c36qmLwzdFDlU5u7QVVrqTNMW-Xcny_15F_Ewny1VQOh40pya40T8qeDA
```
- `duplicate_m_for_missing_sh`: `m` twice and no `sh` (11 entries, wrong set).
```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9jb25maXJtPTEiLCJtIjoiR0VUIn0.T9VZ1vDmIVsJGhs-JzUIIuv7irHuHt0iEoXyPXGbZ_fZu7m3RPmbwCQbK851TaMZ2-QHh2qyeMDKuvLkhQpoAw
```
- `extra_tid`: an extra key `tid`.
```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9jb25maXJtPTEiLCJ0aWQiOiJ0Iiwic2giOiJjc1lldlJ0Qm1ka3BoOWtZVGtuUUgxNWpXd3ZuR0Q4ZGtEQzdpeGMteTJJIn0.mp4oOH_lLO2uil8-pbN3uSK5Et-SDDk2WnnelimGXv4cY_NjR8B5ZExQp6Fv8hWB8C0xKuPk9ySviLEzfln3Bg
```
- `null_name`: `name` is `null`.
```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjpudWxsLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9jb25maXJtPTEiLCJzaCI6ImNzWWV2UnRCbWRrcGg5a1lUa25RSDE1ald3dm5HRDhka0RDN2l4Yy15MkkifQ.3SToDp5y6Uu_vKJeul7Wj6p9NEuJRCUqSlb_YFIvUNLA_DrcGntx6J-2NdlurPh2RZ-sdjqTqn8NsUHL6LkSBA
```
- `short_jti`: `jti` decodes to 15 bytes.
```
v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIyYy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIsImxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2wiLCJtIjoiUE9TVCIsInAiOiIvdm1zL2Rldi9kZWxldGU_Y29uZmlybT0xIiwic2giOiJjc1lldlJ0Qm1ka3BoOWtZVGtuUUgxNWpXd3ZuR0Q4ZGtEQzdpeGMteTJJIn0.0pdcx6NyS6DRj4xlvmmsydOnPfm0uWHlCZUHdXH6Bl--3SfRixQy9j840ui9nhBgZzDaXeZnO-O-kKFBDRxACg
```

## SSO sign-in returns to the control-plane host

An SSO provider whose `return_url_domain` is `external_host` (the default)
sends the browser back to the control-plane host, not to the global
`external_host`. The control-plane host is `http.external_host` when it is
set, otherwise `external_host`.

- **The redirect URI Warpgate sends to the identity provider** is
  `https://<control-plane host>[:<port>]/@warpgate/api/sso/return`. The port
  is the one written in `http.external_host`, else `http.external_port`, else
  the HTTP listener's port, and is left out when it is 443. (With a
  `return_url_prefix` other than the default `@`, the path is
  `/<prefix>warpgate/api/sso/return`.)
- **What operators do on upgrade:** where `http.external_host` names a host
  other than `external_host` (for example `warpgate.<base>` beside
  `<base>`), register that redirect URI, on the control-plane host, with the
  identity provider *before* taking the release, and keep the old one
  (`https://<external_host>[:<port>]/@warpgate/api/sso/return`) registered
  until you no longer need to roll back. Until the new URI is registered,
  every SSO sign-in fails at the provider. Where `http.external_host` is
  unset, nothing changes.
- **A sign-in starts on the control-plane host only.** On any other host,
  `GET /@warpgate/api/sso/providers/<name>/start` answers 400, and
  `GET /@warpgate/api/sso/auto-start` sends the browser to that host's login
  page instead of the provider. On a host bound to a web target neither
  route exists (404; see "What a target's page can do on its own host"); a
  browser there starts its sign-in through the handoff's begin route (see
  "Starting a sign-in from a target's host").
- **Where the browser lands afterwards:** the post-login redirect, and the
  `login_error` redirect of an SSO failure (see "SSO failure"), go to the
  control-plane host's origin, never to the host the visitor came from. A
  `next` of `/cove/login` lands on `https://<control-plane host>/cove/login`.
- Providers with `return_url_domain: host_header` are unchanged: they
  return to the host the sign-in started on.

## Recordings a separate reader can read: `--recordings-keep-group-read`

By default Warpgate sets each recording directory to exactly `0700` and each
recording file to exactly `0600`. That also zeroes the mask of any POSIX ACL,
so no other user can read a recording, whatever ACL the deployment set.

With `--recordings-keep-group-read`, Warpgate secures the recordings tree by
removing bits instead: the recordings root, the session directory and the
recording directory become `current & 0750`, and each recording file it opens
becomes `current & 0640`. It never adds a bit. New directories are created at
most `0750` and new files at most `0640`, so nothing is born wider, even under a
default ACL, where the kernel ignores the umask. The flag does nothing with
`--skip-securing-files`, and nothing outside the recordings tree changes: the
config, database and TLS files are still set to exactly `0600`.

The recordings tree is the disk backend's recordings directory or, with the S3
backend, the local scratch directory that buffers recordings while they upload
(`data/recordings-scratch` unless `scratch_path` is set). The flag covers either
the same way.

With the flag, `warpgate run` refuses to start unless the process umask covers
`0077` (for example `UMask=0077` in the service unit). Every access beyond the
owner then comes from the ACL.

### Granting the reader

The grant that works is a **default POSIX ACL on the recordings root** that
gives the reader read on files and read + execute on directories, plus an
access ACL giving the reader execute on the root itself (and on every
directory above it). The default ACL is what gives the reader access to new
directories and files, and the masking keeps the ACL mask from being zeroed.
Set the default ACL's owning-group and other entries to nothing (`d:g::---`,
`d:o::---`).

A group grant on the root alone (a group-owned root with setgid) does **not**
work: the masking strips setgid, so new directories and files get Warpgate's
primary group, not the root's.

### Limits

- **Existing recordings are never opened up.** A recording made at `0700` /
  `0600` before the flag was on stays that way; the masking only removes bits.
  The deployment must grant read on existing recordings itself.
- **The default ACL must be on the root before the first recording** made with
  the flag on. Directories and files are given their ACL when they are created.
- **A root not owned by Warpgate's user is skipped**, even when Warpgate runs
  as root: its mode is left as it is, a warning naming the root, its owner's
  uid and Warpgate's uid is logged once per process, and recordings still
  start. The same applies when the root cannot be opened or chmodded (for
  example when it is a symlink, which is not followed): one warning per
  process, and recordings still start.
- **The session and recording directories and the recording files are
  Warpgate's own**, and fail closed: a symlink in their place, one owned by
  another user (even when Warpgate runs as root), or a failure to chmod one
  fails the recording start. Each recording file must be new: an existing file
  of that name fails the start too, so starting a recording with the same name
  again is refused under the flag. Below the root, each directory and file is
  created and opened relative to the directory above it, never through a
  symlink, so nothing is created or chmodded through a symlink there, and the
  directory checked is the one written to.
- **The root and the directories above it are resolved by path.** The
  guarantee above holds for a root that only Warpgate's user (and root) can
  change, along with every directory above it; a root someone else can replace
  is outside it.
- **setuid, setgid and sticky are stripped** from the root, as from every
  directory the flag touches.
- **Group read comes only from the ACL's owning-group entry.** Under a default
  ACL a new file's group bits are the ACL mask, and `0640` keeps that at read.
  The mask bounds the named entries and the owning-group entry; it grants
  nothing itself. With the default ACL that grants the reader (`d:g::---`)
  only the named reader entry uses it, and nobody in Warpgate's group can read
  new recordings. Members of the file's group can read only where the default
  ACL's owning-group entry grants read. When a default ACL is set without a
  `g::` entry, `setfacl` fills one in from the root's own owning-group ACL
  entry (not from its mode's group bits, which are the mask once the root has
  an ACL), so set `d:g::---` explicitly. On a host with no ACL, the required
  umask leaves new recordings with no group bits; a directory or file that
  already had group read keeps it, for its owning group (normally Warpgate's
  primary group) only.
- **The result relies on the umask plus the ACL.** The flag only removes bits,
  so every access beyond the owner comes from the ACL (where a default ACL
  applies, the kernel uses it in place of the umask), and the umask, which
  `warpgate run` checks, keeps everything else closed.

## Upstream request errors in the log

When the HTTP proxy, a WebSocket proxy (target or cluster peer) or the
Kubernetes proxy logs a failed upstream request, the line carries no raw query
string, no userinfo and no upstream client URL. Query values are redacted. A
WebSocket upgrade refused through a target or cluster-peer proxy is logged by
its HTTP status only, never with the upstream's headers or body.

### Limits

- **A query key is logged percent-decoded** when, decoded, it looks like a
  parameter name (1 to 40 ASCII letters, digits, `_`, `.`, `-`, `[` or `]`)
  and its value, as sent, is neither empty nor starts with `=`. A credential
  sent in the key position of such a pair appears in the log.
- **A Kubernetes API server's refusal is logged with its body.** When the API
  server refuses a WebSocket upgrade through the Kubernetes proxy (exec,
  attach, port-forward or any other API path), the log line carries its HTTP
  status and response body, and an admission webhook can put any text in
  that body.
- **Debug logging carries content.** At debug level Warpgate logs more than
  this section describes, including: every WebSocket frame the target and
  Kubernetes proxies pass, contents included (for Kubernetes that includes
  exec and attach stdin and stdout); the Kubernetes API server's response
  headers, unredacted; and full redirect and SSO return URLs, query
  included. Everything above holds at info level and above.
- **Path segments are logged as written.** Warpgate's own routes carry only
  IDs there.

## Sessions whose recording fails: `--recordings-refuse-unrecorded-sessions`

A recording fails when it cannot start (for example, with
`--recordings-keep-group-read`, a recording directory that cannot be secured)
or when a write fails after a good start (for example, a full disk). Every
failure, in every protocol, is logged at error level with one line whose
message is exactly

    Session recording failed

with these fields:

- `protocol`: `ssh`, `kubernetes`, `web-ssh`, `web-desktop`, `rdp` or `vnc`
- `user`, `target`: who the session belongs to and where it goes
- `target_session`: the target session's id
- `stage`: `start` (it could not be created) or `write` (a write failed:
  mid-session, or the first write at start described below). A disk that
  takes a new file but not its writes is logged as `write`, so an alert on
  `stage=start` alone misses it
- `cause`: the underlying error
- `required`: whether `--recordings-refuse-unrecorded-sessions` is on
- `total`: how many recordings have failed since Warpgate started

A recording that fails mid-session is logged once, at its first failed write;
it then stops. With S3 storage, a part that cannot be pushed to S3 is such a
failure, logged when the push fails: with the option below on, the recording
stops and its session is closed; with it off, the local scratch copy goes on
being written and is kept, since the upload can no longer be completed. `total` is the same counter for both stages, so an alert can
match the message alone. The text is pinned by a test
(`warpgate_core::recordings::log_text`); a change to it needs every alert that
matches it changed too. Writers closing because Warpgate is shutting down are
not failures and are not logged; a write that really fails while Warpgate
drains its recordings at shutdown is.

This line replaces the texts earlier releases logged when a recording could
not start or write (`Failed to start recording`, `Failed to start terminal
recording`, `Failed to start desktop recording`, `Failed to start desktop
session recording`, `Failed to write recording` and `Failed to write
recording item`). None of them is logged any more: an alert keyed on an old
text reads zero after the upgrade, whatever fails, until it is changed to
match `Session recording failed`.

With `--recordings-refuse-unrecorded-sessions true` (off by default, so a full
disk cannot lock operators out of a host), a session whose recording cannot
start is refused rather than continuing unrecorded:

- **SSH:** the client is shown `session refused: its recording could not be
  started` and the connection is closed. This covers shell and exec channels
  and recorded port forwards. The recording is started before the shell,
  command or forward reaches the target, so a refused session sends none of
  them. A direct port forward opened before its target session exists (while
  an approval is pending) cannot be recorded, so with the option on its open
  is rejected; the client can open it again once the session is approved.
  With the option off, such a forward is held unanswered until the session
  is approved, then recorded and opened like any other forward; nothing of it
  reaches the target before then.
- **Kubernetes:** the API request is answered with that error (HTTP 503) and
  is not forwarded; an exec or attach stream fails before it is opened. An API
  request's recording writes its first line and waits for it to reach the
  file before the request is forwarded, so a disk that takes a new file but
  not its writes refuses the request too. The request's own record is then
  written and waited for in the same way, still before the request is
  forwarded (below). A WebSocket upgrade has no such record, and only an exec
  or attach stream has a recording. So, while recording is switched on, any
  other upgrade (a pod, service or node `proxy` path, for one) is answered
  with that error (HTTP 503) and does not reach the cluster, and the proxy
  logs `Refusing a Kubernetes stream that has no recording`. The one
  exception is port-forward, which is never recorded and is not refused
  (below).
- **Web SSH client:** the shell is not opened on the target; the viewer gets
  the error and the session ends.
- **Web desktop client:** the session ends with the error, before
  Warpgate connects to the desktop.
- **Native RDP and VNC:** the connection is closed.

With the option on, every session also waits for its recording's first write
at start, before anything of it reaches the target: an empty line in the
recording's index (readers skip it), an SSH forward connection's setup
record, or, for a Kubernetes API request, whose recording has no index, an
empty line in its `data.ndjson`, is written and flushed. This covers SSH
channels and forwards, Kubernetes API requests and exec and attach streams,
the web SSH and web desktop clients, and native RDP and VNC. So a disk that
takes a new file but not its writes stops the session at start too. That
failure is a failed write: it is logged with `stage=write`, and what the
client sees depends on the protocol:

- **SSH and the web SSH client:** the session is closed as for a failure
  mid-session (below): the client is shown `session closed: its recording
  failed`, and nothing of the channel or forward reaches the target.
- **Kubernetes, the web desktop client, native RDP and VNC:** the session is
  refused exactly as when its recording cannot start (above): the error is
  `session refused: its recording could not be started` (HTTP 503 for a
  Kubernetes API request), and native RDP and VNC close the connection.

The flush hands the write to the operating system; it does not wait for it to
reach the disk (see the limits below). With S3 storage this write reaches
the local scratch copy only; S3 itself is reached later (see below).

With the option on, SSH also drops client data it has no recording for,
rather than forward it: data on a session channel before the channel's shell,
exec or subsystem request (the target's channel is already open by then, and
some SSH servers hand such data to the command's stdin; OpenSSH's server
discards it), and extended data the client sends on any channel, which is
never recorded (OpenSSH's server discards that too).

With the option on (and recording on), SSH refuses X11 forwarding and agent
forwarding, which are never recorded: the client's request is not passed to
the target and is answered with a failure (OpenSSH's client goes on without
the forwarding), and an X11 or agent channel the target opens is closed
before it reaches the client.

With the option on (and recording on), SSH refuses every subsystem request
on a session channel, SFTP and any other, since a subsystem is never
recorded: the request is not passed to the target and is answered with a
failure (OpenSSH's `sftp` client reports `subsystem request failed on
channel 0` and exits), and Warpgate logs `Refusing a subsystem request:
recording is required and a subsystem cannot be recorded` with the
subsystem's name. This holds while an approval gate holds the session too:
the request is refused when it is made, not kept for after the approval. The
session itself stays open. `scp` in its SFTP mode (OpenSSH 9.0 and later by
default) is such a request; `scp -O` is an exec and is recorded as one.

With the option on, a Kubernetes exec or attach stream that has a recording
goes on only in a form the recording can hold, which is binary websocket
frames on one of the `channel.k8s.io` subprotocols Warpgate offers
(`channel.k8s.io` and `v2.` to `v5.channel.k8s.io`). The client names the
subprotocols it asks for (in the base64 ones the same stdin and stdout
travel encoded), and of those Warpgate asks the cluster only for the ones
above, so the cluster is not asked for a stream the recording cannot hold. A
client that names none of them is refused before the stream reaches the
cluster (HTTP 503, `session refused: its recording could not be started`),
and the proxy logs `Refusing a Kubernetes stream: the client offers no
subprotocol that can be recorded`. If the cluster answers with a subprotocol
it was not asked for, or with none, the stream fails as it opens, before any
frame passes; the cluster has accepted the stream by then, so an exec's
command (which is in the recording's metadata and the audit event) may have
started, with no input.
On a subprotocol that can be recorded, the stream is closed at the first
text frame from either side, before that frame is passed on, and the proxy
logs `Closing the Kubernetes stream: a text frame cannot be recorded`. Ping,
pong and close frames carry no stream data and pass.

With the option on, a recording that fails mid-session closes the session
too: in SSH (the client is shown `session closed: its recording failed`), the
web SSH client, Kubernetes exec and attach streams, native RDP and VNC, and
the web desktop client. In SSH and the web SSH client, nothing more passes
once the session is closed for its recording. A Kubernetes API request is
recorded twice in its `data.ndjson`: a line with the request and no response
(`response_status` and `response_body` are `null`) before the request is
sent, and a line with the request and its response afterwards; a request
with the first line only was not answered, and may not have reached the
cluster. With the option on,
the first line is waited for before the request is sent, and if that write
fails the request is refused (HTTP 503, `session closed: its recording
failed`) and never reaches the cluster. A Kubernetes API request that
has already been sent to the cluster still gets its response, since failing
it would hide whether it was applied; but its write is waited for, and once a
write of a Kubernetes session's recording has failed, every later API request
of that session is refused (HTTP 503, `session closed: its recording
failed`) without being forwarded. In native RDP, with the option on, a
recording that falls behind the session (its queue of 256 frames is full) is
a failure too, and closes the session before that frame reaches the viewer.

The close is not instant. Writes go through a queue of 1024 items per
recording file, and the disk write happens behind it. At start this is
checked: the first write is waited for, as above, but only until the
operating system has taken it, not until it is on disk. A filesystem that
reports a lack of space only when it writes its cache back (some network
filesystems, or a thin-provisioned volume) passes that
check, and its failure surfaces at a later write, as a failure mid-session.
After that, a failure mid-session is still found only at the session's next
write after it; what the session sent or showed in between was passed on and
may not be on disk.
A Kubernetes exec or attach stream passes each frame on once it is in a queue
of 1000 frames in front of its recorder, so the stream can be up to that many
frames ahead of the recorder when a write fails. With S3 storage, the upload
is pushed in 5 MiB parts and completed when the recording ends, so a push
failure is only seen at a part push or at that final push. A failure at the
final push comes after the recording's last write: it is logged and counted,
and the recording's local scratch copy is kept. The Kubernetes API is a known
limit here: each API request has its own recording, usually far smaller than
one part, so with S3 storage nothing of it reaches S3 until that final push,
after the response, and an S3 failure is only seen then. It is logged and
counted and the scratch copy is kept, but the session's later requests are
not refused and go on. In native RDP,
frames already queued for the viewer still reach it: up to 16 in the queue
into Warpgate's viewer-facing RDP server and up to 256 display updates in the
queue behind it, inside that server. The target connection is cut off at
once, even if the viewer has stopped reading. In the desktop
protocols, only what is written to the recording can show a failure: pixel
updates are written at most 30 times a second, and the desktop's clipboard
text and cursor shapes, and keyboard input that is not recorded (keyboard
recording off, or the logon screen showing), are not written, so they pass
until the next write fails. In SSH a forward's connection writes its first
record (its setup record) before the forward opens, so a forward recorder
that has already failed is caught before the forward reaches the target; and
since that record comes before the other side accepts the forward, a forward
that is then refused still leaves a setup record.

With the option off (the default), nothing is closed or refused: the failure
is still logged with the line above and counted, and the session continues
unrecorded. Whether a host turns it on is for the host's owner: it
trades access during an incident for the audit trail.

What the option does not cover:

- **Recording switched off** in the settings is not a failure and refuses
  nothing. Nor does repointing the recordings root through the admin
  settings (ConfigEdit): a session whose recording starts under the new root
  is recorded there, and nothing is refused.
- **What is never recorded**, so never refused for want of a recording:
  `scp` with `record_scp` off while the option is off (this leaves any exec
  whose command starts with `scp ` unrecorded, not only scp transfers, for
  example `scp -V; exec sh`; with the option on and recording switched on,
  the option overrides `record_scp`: the `scp` exec is recorded like any
  other exec, and Warpgate logs one warning saying so), SSH
  extended data sent from the client to the target, Kubernetes port-forward,
  Kubernetes exec and attach websocket text frames, and every frame of an
  exec or attach stream on a subprotocol other than the `channel.k8s.io`
  ones above, with the option off (with it on the first close the stream and
  the second is not opened, above), every other Kubernetes WebSocket upgrade
  with the option off (with it on it is refused, above),
  the bodies of streamed Kubernetes API responses to reads (`watch`, `logs -f`
  and other chunked responses; the request and its response are recorded,
  with an empty response body), native RDP frames dropped from the recording
  when its queue is full with the option off (no failure line is logged for
  them), and MySQL, PostgreSQL and HTTP targets. SSH subsystems (SFTP and
  every other), X11 and agent forwarding are never recorded either; with
  the option on they are refused (above), and with it off they pass
  unrecorded.
- **Connecting before the recording starts.** With the option on, Warpgate
  may connect and authenticate to the target before a recording exists: for
  a `tcpip-forward` or `streamlocal-forward` request, and for a web SSH
  client session, which connects when the session
  is created. No shell, command or forward reaches the target before its
  recording has started. Input follows the same rule: while an SSH session
  waits for an approval gate, a shell or exec request on a session channel
  has its recording started only once the gate is approved, and what the
  client sends on that channel during the wait is held, whether or not
  recording is required. Once the recording has started it is written to the
  recording and passed to the target, in the order it was sent. With the
  option on, if the recording fails to start, none of it is passed to the
  target and the target is not dialled. A channel closed during the wait
  passes none of its held input, and its queued shell or exec request does
  not run.

## Web targets need a hostname of their own

An HTTP target is served only on the hostname it is bound to
(`external_host`). An HTTP target with no `external_host` is not served at
all: opening it, by name (`?warpgate-target=`), from a session or with a
ticket, gets no page from the target.

- **What operators do on upgrade:** give every HTTP target a hostname of its
  own (a DNS name that points at Warpgate, covered by its TLS certificate) and
  set it as the target's `external_host` before taking the release.
- **The way back, for a deployment that cannot do that yet:** set
  `http.serve_unbound_http_targets: true` in the config file. Targets with no
  hostname are then served as before, on Warpgate's own host, and Warpgate
  logs a warning at every start and shows it in the admin UI. The setting is
  read from the config file only; the admin API and UI cannot change it. It is
  meant to be turned off again once every web target has a hostname.
- The default is `false`. Bound targets behave the same either way.

## A step-up ends older target-host sessions

A browser gets a session on a target's own hostname through a one-time
handoff from the control-plane host; that session carries the time of the
SSO sign-in it was handed off from. When the same sign-in (user session)
completes a later SSO sign-in, a step-up, Warpgate records the later time for
every node to see.

- From then on, every target-host session still carrying an earlier sign-in
  is refused on its next request and deleted, so it never acts again. The
  browser starts a new handoff on that host, which carries the later sign-in.
- Only those target-host sessions end: the control-plane sign-in, its user
  session and target-host sessions already handed the later sign-in go on.
- A step-up Warpgate forces because the configured HTTP step-up interval
  has passed is different: it ends the control-plane sign-in itself, with its
  user session and every target-host session handed off from it, before the
  browser signs in again. Nothing from the old sign-in acts again.
- A sign-in that never used SSO records nothing and ends nothing this way.

## What a target's page can do on its own host

A page a target serves on its own hostname shares that origin with the
browser's session there. Through that session the page can:

- Make requests to its own target on its own host as the signed-in user. The
  target receives `X-Warpgate-Username` (the user's name) and
  `X-Warpgate-Authentication-Type: user`.
- Load Warpgate's gateway assets under `/@warpgate/assets/`.
- Sign that host's browser session out (`POST /@warpgate/api/auth/logout`).
  That ends the session on this host only; the control-plane sign-in and the
  sessions on other target hosts go on.
- Send the browser to the handoff's begin route
  (`/@warpgate/handoff/begin?next=<path>`), which starts a sign-in (see
  "Starting a sign-in from a target's host").
- Send the browser to the handoff's redeem route (`/@warpgate/handoff`). It
  signs a browser in, on this host only, with a token handed off for this
  host's target to that same browser.

Every other route under `/@warpgate` and `/_warpgate` on that host answers
404, and the session counts nowhere else: not on the control-plane host and
not on another target's host. The target never receives a Warpgate cookie,
and a cookie it sets under a Warpgate cookie name never reaches the browser.

A target-host session never ends the control-plane sign-in it was handed off
from. Signing out, a sign-in started on that host (as the same user or
another, which gets a sign-in of its own) and its user being deleted or no
longer admitted from the request's address end that host's browser session
only. A ticket presented with it is ignored and keeps its uses, whoever it
was issued to. A handoff token refused on that host leaves the session there
as it is, with one exception: a token whose control-plane sign-in has ended,
or is not this user's HTTP sign-in, ends that host's browser session. Either
way, a refused token never leaves a session signed in on that host.

On a plain-HTTP loopback listener (`http.plain_http_on_loopback`) a bound
target cannot be reached by a signed-in session: the handoff needs HTTPS (its
cookie is a `__Host-` cookie, which that listener neither reads nor sets), so
the browser never gets a session on the target's host there. This fails
closed: the target is not served as the signed-in user.

## Starting a sign-in from a target's host

A browser on a host bound to a web target signs in on the control-plane
host and is handed back. On a target that is not public this starts by
itself: a navigation without a session there is sent through the handoff.
A public target's pages are served without a sign-in, so nothing starts
one; a page that wants its visitor signed in sends the browser to

    GET /@warpgate/handoff/begin?next=<path>

on its own host, as a top-level navigation over HTTPS (a request that is
framed, that is, one whose `Sec-Fetch-Dest` is present and not `document`, is
refused; a browser that sends no `Sec-Fetch-Dest` is not).

- `next` is the page on this host to come back to. It is checked as the SSO
  `next` is (see "SSO failure"): a site-relative path, still one after
  decoding. Any other `next`, or none, answers 400.
- The route starts the same handoff an unauthenticated navigation starts: it
  records the handoff, sets the `__Host-warpgate-handoff` cookie on this host
  (Secure, HttpOnly, SameSite=Lax) and sends the browser to the control
  plane's handoff start. It changes nothing else: no session is written or
  ended.
- The host the browser returns to is the target's configured
  `external_host`, never one taken from the request (`Host`,
  `X-Forwarded-Host` or any other header). Off a bound host the route answers
  404.
- On the control plane a browser that is not signed in goes to the login
  page and comes back through the same handoff once it is. A user without
  access to the target is refused there and gets no session on the target's
  host. The handoff completes only in the browser that began it (the cookie
  holds a nonce the redeem checks); it is single-use and lasts 120 seconds.
- A request that is not a navigation, is framed, or is not over HTTPS, gets 403.

## Public web targets (`public: true`)

A web target with `public: true` (and `require_approval: false`) is served
on its own hostname without a sign-in. Who the target is told it is serving:

- **An anonymous visitor** is served as `<public>`: an identity with the nil
  user id, which no credential produces. The target receives no
  `X-Warpgate-Username` and no `X-Warpgate-Authentication-Type` header. The
  visitor's browser session is not changed and no cookie is set.
- **A visitor with a session on this host from a handoff** (see "Starting a
  sign-in from a target's host") is served as that session's user.
- **A visitor signed in only on the control-plane host** is served as
  `<public>`: a control-plane session never names anyone on a target's host,
  even if it reaches it.
- **A visitor holding a ticket for this target** is served as the ticket's
  user (`X-Warpgate-Authentication-Type: ticket`). A ticket for another
  target names no one here.
- **An API token or the admin token** gets 401: tokens do not open web
  targets.

The identity named to a public target is only ever the one Warpgate checked
for this host: the handoff session made for this target on this host, or a
ticket for this target. Anyone else is `<public>`.

## Sign-in handoff limits

Each step of a handoff is rate-limited per client address, on each node.

- Behind a reverse proxy or tunnel that connects to Warpgate from 127.0.0.1
  (nginx, cloudflared), every client has that one address, so all of them
  share one rate-limit bucket. On such a deployment set
  `http.client_ip_header` to the header the proxy fills with the client's
  address (for example `CF-Connecting-IP` behind cloudflared).
- One target host's share of the handoff store is small: a handful of client
  addresses (about 5 to 9) opening handoffs as fast as the rate limit allows
  can block new sign-ins to that host until their entries expire.

## Rolling back to the previous release

The way back from this release is to deploy the previous release,
v0.30.2-cove.29. That release refuses to start on a database this release
has migrated (`Migration file of version 'm00097_cove_http_sso_stamps' is
missing`), so the database goes back first:

1. Stop every Warpgate node, and keep them all stopped until step 4.
2. With the database's own client (`sqlite3`, `psql` or `mysql`), delete
   every row of `http_sessions`: `DELETE FROM http_sessions;`. The previous
   release cannot use this release's sessions, so they must go. This step is
   required: step 3 refuses while any row remains, and leaves the two
   handoff tables as they were when it refuses.
3. Once, against the shared database, with this release's binary and config:
   `warpgate --config <config> migrate-database -3 --destructive`. This
   reverts `m00098_cove_statement_keys`, `m00097_cove_http_sso_stamps` and
   `m00096_cove_http_handoffs`, dropping their three tables. They hold only short-lived handoffs,
   sign-in times and the statement signing keys; the previous release uses none of
   them. The statement-key table goes first, so a refusal here can leave it
   already dropped; the other two tables stay.
4. Deploy the previous release.

The check in step 3 relies on step 1: no node may be running to write a
session while the rollback runs. On PostgreSQL the rollback also locks
`http_sessions` against new rows until it finishes. On MySQL (and SQLite)
there is no equivalent lock, so the row count is advisory only: it is right
when taken, and only step 1 keeps it right until the tables are dropped.
On MySQL each table drop commits on its own, so a session written between
the migrations leaves the rollback part done, with
`m00098_cove_statement_keys` and `m00097_cove_http_sso_stamps` reverted and
`m00096_cove_http_handoffs` refusing. To finish, stop whatever wrote it,
delete the rows again and run `migrate-database -1 --destructive`.

What users see afterwards:

- Every browser is signed out, on the control-plane host and on target
  hosts, and signs in again on the control plane. The previous release reads
  only the `warpgate-http-session` cookie, which this release never sets and
  expires; this release's `__Host-warpgate-http-session` and
  `__Host-warpgate-handoff` cookies are ignored.
- A new sign-in works on the previous release as it always did there.
- The previous release serves targets with no hostname on Warpgate's own
  host again, whatever `http.serve_unbound_http_targets` says; it warns that
  the key is unknown. Remove the key to silence the warning.
