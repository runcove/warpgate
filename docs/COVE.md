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

## Recordings a separate reader can read: `--recordings-keep-group-read`

By default Warpgate sets each recording directory to exactly `0700` and each
recording file to exactly `0600`. That also zeroes the mask of any POSIX ACL,
so no other user can read a recording, whatever ACL the deployment set.

With `--recordings-keep-group-read`, Warpgate secures the recordings tree by
removing bits instead: the recordings root, the session directory and the
recording directory become `current & 0750`, and each recording file it opens
becomes `current & 0640`. It never adds a bit. The flag does nothing with
`--skip-securing-files`, and nothing outside the recordings tree changes: the
config, database and TLS files are still set to exactly `0600`.

### Granting the reader

The grant that works is a **default POSIX ACL on the recordings root** that
gives the reader read on files and read + execute on directories, plus an
access ACL giving the reader execute on the root itself (and on every
directory above it). Run Warpgate with `UMask=0077`; the default ACL is what
gives the reader access to new directories and files, and the
masking keeps the ACL mask from being zeroed. The alternative is a group that
Warpgate's own user belongs to, running with a umask that leaves group read.

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
  process, and recordings still start. The session and recording directories
  and the recording files are Warpgate's own: a failure to secure them (a
  symlink in their place included) fails the recording start.
- **setuid, setgid and sticky are stripped** from the root, as from every
  directory the flag touches.
- **The owning group gains read on new files.** Under a default ACL a file's
  group bits are the ACL mask, and `0640` keeps that at read, so the default
  ACL's owning-group entry applies to new recordings. `setfacl` copies that
  entry from the root's group bits unless it is given, so Warpgate's primary
  group can read new recordings unless the default ACL sets `g::---`.
- **The result relies on `UMask=0077` plus the ACL.** The flag only removes
  bits, so every access beyond the owner comes from the ACL (where a default
  ACL applies, the kernel uses it in place of the umask), and the umask keeps
  everything else closed. With a wider umask, the group can read recordings
  without any ACL.
