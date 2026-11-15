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
- A sign-in that never used SSO records nothing and ends nothing this way.

## Rolling back to the previous release

The way back from this release is to deploy the previous release,
v0.30.2-cove.24. That release refuses to start on a database this release
has migrated (`Migration file of version 'm00097_cove_http_sso_stamps' is
missing`), so the database goes back first:

1. Stop every Warpgate node, and keep them all stopped until step 4.
2. With the database's own client (`sqlite3`, `psql` or `mysql`), delete
   every row of `http_sessions`: `DELETE FROM http_sessions;`. The sessions
   must go because the previous release would pass this release's session
   cookies on to targets. This step is required: step 3 refuses while any
   row remains, and changes nothing when it refuses.
3. Once, against the shared database, with this release's binary and config:
   `warpgate --config <config> migrate-database -2 --destructive`. This
   reverts `m00097_cove_http_sso_stamps` and `m00096_cove_http_handoffs`,
   dropping their two tables. They hold only short-lived handoffs and
   sign-in times; nothing in them needs keeping.
4. Deploy the previous release.

The check in step 3 relies on step 1: no node may be running to write a
session while the rollback runs. On PostgreSQL the rollback also locks
`http_sessions` against new rows until it finishes. On MySQL (and SQLite)
there is no equivalent lock, so the row count is advisory only: it is right
when taken, and only step 1 keeps it right until the tables are dropped.
On MySQL each table drop commits on its own, so a session written between the two migrations leaves
the rollback one step done, with `m00097_cove_http_sso_stamps` reverted and
`m00096_cove_http_handoffs` refusing. To finish, stop whatever wrote it,
delete the rows again and run `migrate-database -1 --destructive`.

What users see afterwards:

- Every browser is signed out, on the control-plane host and on target
  hosts, and signs in again on the control plane. The previous release reads
  only the `warpgate-http-session` cookie, which this release never sets and
  expires; this release's `__Host-warpgate-http-session` and
  `__Host-warpgate-handoff` cookies are ignored.
- A new sign-in gets the previous release's domain-wide cookie, so target
  hosts under Warpgate's own hostname work as before this release.
- The previous release serves targets with no hostname on Warpgate's own
  host again, whatever `http.serve_unbound_http_targets` says; it warns that
  the key is unknown. Remove the key to silence the warning.
