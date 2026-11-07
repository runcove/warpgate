# Agent instructions

This is runcove's fork of [Warpgate](https://github.com/warp-tech/warpgate). Most changes belong
upstream; this fork carries the patches runcove's products need on top of an upstream release.

## Read first

The maintainers' rules live in the runcove repository, which is private:

- `AGENTS.md` at its root: the house rules every agent follows.
- `ways-of-working/README.md`, section **Start now**: how work starts, waits and lands.

## This repository's own rules

- **Everything here is public.** Every branch, commit message, tag and PR text is mirrored to
  public GitHub within minutes, and the mirrors never prune. Keep internal names, hosts and
  addresses out of them, and keep the detail of an unreleased security fix out of all of them
  until the fix is released.
- **Never bypass the pre-push hook.** It is the publish gate; a push it has not examined is
  not made.
- **Changes land on the release line** (`cove-patches-v*`) through a reviewed PR, never by a
  direct push. Release tags are made by the release bot only.
- **Commits are signed.**
- **`docs/COVE.md` is a contract.** It lists the behaviour cove depends on; changing that
  behaviour, or the file, means telling cove before it lands.
- **Vendored crates record their patches.** A change under `vendor/<crate>/` updates that
  crate's `PATCHES.md`.
- **Fork database migrations are named `m000NN_cove_*`,** so they never collide with
  upstream's.
- **Docs are part of done:** a change lands with the doc updates it needs, in the same PR.
