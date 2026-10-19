Fork of `russh` 0.64.1.

The package is the crates.io release, unmodified apart from the changes below.
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

## Window credit counted twice on window adjust

Upstream pull request [russh#790][2] (also russh#789), applied as published against the commit
0.64.1 was released from. On `CHANNEL_WINDOW_ADJUST` both sides *set* the writers' window
credit (`WindowSizeRef`) to the session's remaining window. Writers take from that credit when
they queue a chunk, before the session sends it, so the remaining window still counts every
queued chunk and their share is handed out twice. Writers then queue past the peer's window and
the excess lands in `pending_data`, which is what the fix above then has to clean up when the
peer closes the channel. `WindowSizeRef::update(value)` becomes `grow(amount)`: the adjust
handlers add the granted amount, and the channel-open paths add the initial window (the credit
is 0 until then). `ChannelMsg::WindowAdjusted` and `Handler::window_adjusted` still report the
new total. The PR's integration test is `tests/test_window_adjust.rs`, with a `[[test]]` entry
added to `Cargo.toml` (the published manifest lists its tests explicitly).

## Manifest

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. Neither
`Cargo.toml` change is in `warpgate.patch` (which covers `src/` and `tests/` only); re-apply
them by hand on re-vendor.

Drop this fork once russh publishes a release that fixes #789 (both parts).

[1]: https://github.com/Eugeny/russh/issues/789
[2]: https://github.com/Eugeny/russh/pull/790
