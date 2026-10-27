Fork of `russh` 0.65.0.

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

## Manifest

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. That change is
not in `warpgate.patch` (which covers `src/` and `tests/` only); re-apply it by hand on
re-vendor.

Drop this fork once russh publishes a release that fixes #789. The window-credit fix we carried
for 0.64.1 ([russh#790][2]) is in 0.65.0 (commit 13c94f0) and is no longer patched.

[1]: https://github.com/Eugeny/russh/issues/789
[2]: https://github.com/Eugeny/russh/pull/790
