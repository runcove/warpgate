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
- `stage`: `start` (it could not start) or `write` (it failed mid-session)
- `cause`: the underlying error
- `required`: whether `--recordings-refuse-unrecorded-sessions` is on
- `total`: how many recordings have failed since Warpgate started

A recording that fails mid-session is logged once, at its first failed write;
it then stops. `total` is the same counter for both stages, so an alert can
match the message alone. The text is pinned by a test
(`warpgate_core::recordings::log_text`); a change to it needs every alert that
matches it changed too. Writers closing because Warpgate is shutting down are
not failures and are not logged.

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
- **Kubernetes:** the API request is answered with that error (HTTP 503) and
  is not forwarded; an exec or attach stream fails before it is opened.
- **Web SSH client:** the shell is not opened on the target; the viewer gets
  the error and the session ends.
- **Web desktop client:** the session ends with the error, before
  Warpgate connects to the desktop.
- **Native RDP and VNC:** the connection is closed.

With the option on, a recording that fails mid-session closes the session
too: in SSH (the client is shown `session closed: its recording failed`), the
web SSH client, Kubernetes exec and attach streams, native RDP and VNC, and
the web desktop client. In SSH and the web clients, the data whose recording
failed is not passed on. A Kubernetes API request that has already been sent to the cluster still gets
its response, since failing it would hide whether it was applied; the next
request starts a new recording and is refused if that cannot start.

With the option off (the default), nothing is closed or refused: the failure
is still logged with the line above and counted, and the session continues
unrecorded. Whether a host turns it on is for the host's owner: it
trades access during an incident for the audit trail.

What the option does not cover:

- **Recording switched off** in the settings is not a failure and refuses
  nothing. Nor does repointing the recordings root through the admin
  settings (ConfigEdit): a session whose recording starts under the new root
  is recorded there, and nothing is refused.
- **What is never recorded**, so never refused for want of a recording: the
  SSH SFTP subsystem, X11 and agent-forwarding channels, `scp` with
  `record_scp` off, and MySQL, PostgreSQL and HTTP targets.
