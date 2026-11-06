Fork of `russh` 0.65.1.

The package is the crates.io release, unmodified apart from the change below.
`LICENSE.txt` is the upstream repository's licence file at the commit the crate was published
from (see `.cargo_vcs_info.json`): the published package ships none.

## A channel the peer closes with data still waiting for window stalls the connection

Upstream issue [russh#789][1]. When a write is larger than the peer's window, russh parks the
rest in the channel's `pending_data`. The session loop stops taking anything from the `Handle`
queue while *any* channel has pending data. If the peer then sends `CHANNEL_CLOSE` for that
channel, `Encrypted::close` sees the pending data, only sets `pending_close` and keeps the
channel. The peer grants no more window on a closed channel, so the data never drains, and from
then on nothing that goes through a `Handle` (data, EOF, close, channel open, disconnect) is
sent on that connection again, for any channel. Keepalives are written directly, so the
connection looks healthy.

`Encrypted::close_by_peer` drops the channel's pending data and its deferred EOF and close,
then closes it at once. Both `CHANNEL_CLOSE` handlers (`server/encrypted.rs`,
`client/encrypted.rs`) call it instead of `close`. RFC 4254 §5.3: once a party has sent
`CHANNEL_CLOSE` it accepts no more data on the channel, so discarding it loses nothing. This
covers both orders of close: the peer closing first, and our own close that had been deferred
behind pending data. Two unit tests in `src/session.rs` cover them.

## A server cannot hold back one channel's receive window

Not reported upstream yet (draft kept outside the tree). russh replaces a channel's receive
window itself (`Encrypted::adjust_window_size`, called before `Handler::data`), so a handler
that cannot take more data on one channel can only await inside `data()`, which stops the
session loop reading the socket for every channel, or buffer without a limit.

`Handle::hold_window(channel, hold)` starts or ends holding one channel's window. It is a
`Msg::WindowHold` on the unbounded priority queue, so it never waits and, like every message on
that queue, is handled outside a key exchange. `Session::held_windows` records the held
channels; for those, `server/encrypted.rs` calls `adjust_window_size` with a target of 0, which
uses the window up but never falls below half of it, so no `CHANNEL_WINDOW_ADJUST` is sent.
Ending the hold calls `adjust_window_size` with no data and the real target, which sends what
was withheld through the same path as any other adjustment. The window counters are not touched
by a rekey. Default behaviour is unchanged without a call to `hold_window`. One unit test in
`src/session.rs`. The caller must end the hold when the channel closes.

## Manifest

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. That change is
not in `warpgate.patch` (which covers `src/` and `tests/` only); re-apply it by hand on
re-vendor.

Drop this fork once russh publishes a release that fixes #789. The window-credit fix we carried
for 0.64.1 ([russh#790][2]) is in 0.65.0 and later (commit 13c94f0) and is no longer patched. 0.65.1 needed no change to the patch.

[1]: https://github.com/Eugeny/russh/issues/789
[2]: https://github.com/Eugeny/russh/pull/790
