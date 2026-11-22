# Behaviour the cove fork promises to cove

This file lists the fork behaviour cove depends on. A change here is a change
to a contract: tell cove before it lands.

## SSO failure: `login_error` and `retry_after` on the caller's `next`

When an SSO login started with a `next` query parameter, a failure at the SSO
return (`/@warpgate/api/sso/return`) sends the browser back to that `next`
instead of to the `/@warpgate` login page.

Only a safe `next` qualifies: a site-relative path starting with a single `/`
(not `//`, not `/\`, not an absolute URL). The redirect goes to the origin the
SSO return URL named, so `next` can never carry the browser off-site.

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
- a ticket session gets 403 (above).

The return stamps the session's `last_sso_at`. A password, OTP or passkey
sign-in never does, so `?login=password` never makes a session fresh.

### What `last_sso_at` means

`last_sso_at` means "Warpgate finished an SSO return at time t". Warpgate
stamps it from its own clock at the SSO return
(`warpgate-protocol-http/src/api/sso_provider_list.rs`); the ID token's
`auth_time` is not used, and nothing sends `prompt=login` or `max_age`.

It is only as fresh as the identity provider's own re-prompt policy. While
the provider's session lives, another site can navigate the browser through
`/sso/auto-start?force=1` (an unauthenticated GET; the session cookie is
`SameSite=Lax`, so it is sent on a top-level navigation) and refresh the stamp
with no user action. So `last_sso_at` is not an intent token and not a CSRF
token: a verifier (cove) must keep its own CSRF check and must not read a
recent `last_sso_at` as proof that the user just chose to act.

A follow-up (W3) will make `force=1` send `prompt=login` and `max_age=0` and
stamp `last_sso_at` from the identity provider's sign-in time (the ID token's
`auth_time`); until it lands, the above holds. The signed statement carries no
`auth_time` of its own.

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
(`external_host` non-empty) carries none either, for anyone. The statement is
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
- `last_sso_at` is Warpgate's own clock at the SSO return, as in "What
  `last_sso_at` means" above. A follow-up (W3) will instead stamp it from the
  identity provider's sign-in time. No other sign-in time is in the statement:
  there is no `auth_time`.
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
says an SSO return finished at that time (see "What `last_sso_at` means"); it
does not show the user's intent, and the verifier's own CSRF check stays.

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
