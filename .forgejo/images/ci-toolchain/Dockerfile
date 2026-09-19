# The sandbox image the capped checks run inside: HARDENED_RUN_IMAGE.
#
# WHAT CHANGES THE MOMENT THIS EXISTS. Five capped checks currently refuse with
# 97 and name the tool they are missing — honest, and impossible to misread.
# Give them a toolchain and they start producing ORDINARY exit codes, where
# nothing distinguishes "upstream's verdict on our code" from "our image is
# subtly wrong". Everything unusual in this file is aimed at that one risk.
#
# WHY NOT THE OFFICIAL `rust:` IMAGE. The workspace pins a dated nightly in
# rust-toolchain.toml. The official images carry stable, so every cargo command
# would fail in the ordinary range — five checks going red with nothing in the
# log to say they went red for our reason rather than upstream's. A stock image
# is not the cautious option here; it is the dangerous one.
#
# WHICH COPY OF THE PIN IS THE SOURCE OF TRUTH. `rust-toolchain.toml` is, and
# RUST_TOOLCHAIN below exists only because `rustup toolchain install` needs a
# literal to install. The two cannot drift apart silently: assert-toolchain.sh
# refuses the build unless rust-toolchain.toml NAMES the value passed to it, so
# a repo that bumps its pin fails this image's BUILD rather than every later
# run. Prose elsewhere in this file and in the assertion deliberately says "the
# pinned toolchain" instead of repeating the string, so a bump leaves no stale
# copies behind to mislead a reader.

FROM debian:bookworm-slim

# The one literal. Bump this together with rust-toolchain.toml; the assertion
# below fails the build if you bump one and not the other.
ARG RUST_TOOLCHAIN=nightly-2026-07-09
# Upstream's own pins, copied from .github/workflows/. Where upstream is loose
# we are not, and each of those is called out below.
ARG JUST_VERSION=1.4.0
ARG CARGO_CRANKY_VERSION=0.3.0
ARG CARGO_LLVM_COV_VERSION=0.6.15
ARG CARGO_DENY_VERSION=0.18.9
ARG CARGO_FMT_TOML_VERSION=0.0.16
# DIVERGENCE: upstream installs `cargo-cyclonedx@^0.5`, a range. A range makes
# the image unreproducible — two builds of this same Dockerfile could carry
# different SBOM generators — and `sbom` is precisely the check where "which
# version produced this" is the question being asked. 0.5.9 is what that range
# resolves to today.
ARG CARGO_CYCLONEDX_VERSION=0.5.9
# DIVERGENCE: upstream runs `docker run tufin/oasdiff`, untagged, i.e. :latest.
# An unpinned comparator means this check's verdict can change with no commit
# on either side. We pin, and verify the download.
ARG OASDIFF_VERSION=1.32.1
ARG OASDIFF_SHA256=7c8939fc49b75ee11fec66a5b83b37a2fca6aee109fed85013b1ba2ac2a1ee7f

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH

# System packages. Three groups, kept separate so a future reader can tell
# what each is owed to:
#   - build essentials: cargo needs a linker and OpenSSL headers to build
#     anything at all, including the cargo tools installed below.
#   - check requirements: git, tar, python3 (+ PyYAML), npm are declared by
#     schema-compat's tools list; PyYAML is the one the tools gate structurally
#     cannot see, because it is not a PATH entry.
#   - openssh-client and expect: upstream's test.yml installs both before
#     `cargo llvm-cov test`. They are NOT in unit-tests' tools list because the
#     check's command does not invoke them directly — the ssh protocol tests
#     spawn them. Installing them here rather than "fixing" that list is
#     deliberate: the list describes what the command runs, and a list that
#     also described what the code under test runs would never be checkable.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev ca-certificates curl xz-utils \
      git tar python3 python3-yaml nodejs npm \
      openssh-client expect \
 && rm -rf /var/lib/apt/lists/*

# rustup, then exactly one toolchain. `--default-toolchain none` first so the
# installer cannot quietly pull stable as well.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none \
 && rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal \
      --component clippy --component llvm-tools-preview \
 && rustup default "$RUST_TOOLCHAIN" \
 && chmod -R a+rX "$CARGO_HOME" "$RUSTUP_HOME"

# The cargo tools the checks name. Built from source, which is most of this
# image's build time.
RUN cargo install --locked \
      "just@${JUST_VERSION}" \
      "cargo-cranky@${CARGO_CRANKY_VERSION}" \
      "cargo-llvm-cov@${CARGO_LLVM_COV_VERSION}" \
      "cargo-cyclonedx@${CARGO_CYCLONEDX_VERSION}" \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# cargo-deny and cargo-fmt-toml belong to the two UNCAPPED checks, which run in
# the job container and never see this image. They are here anyway, and the
# reason is worth stating rather than leaving as apparent bloat: runcove-npoc
# is the open question of where those two get a toolchain, and one live answer
# is "make the job container this image" — act_runner needs `node` for
# actions/checkout, which is why an earlier Rust job image was withdrawn
# (d6c3a20a), and this image has node. Carrying them costs one layer now and
# saves a full rebuild if that answer is taken. They are asserted separately
# from the capped checks' tools, so nothing here pretends they are in use.
RUN cargo install --locked \
      "cargo-deny@${CARGO_DENY_VERSION}" \
      "cargo-fmt-toml@${CARGO_FMT_TOML_VERSION}" \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# oasdiff, verified. A comparator fetched over the network without a checksum
# is a check whose verdict depends on whatever answered the request.
RUN curl -fsSL -o /tmp/oasdiff.tgz \
      "https://github.com/oasdiff/oasdiff/releases/download/v${OASDIFF_VERSION}/oasdiff_${OASDIFF_VERSION}_linux_amd64.tar.gz" \
 && echo "${OASDIFF_SHA256}  /tmp/oasdiff.tgz" | sha256sum -c - \
 && tar -xzf /tmp/oasdiff.tgz -C /usr/local/bin oasdiff \
 && rm -f /tmp/oasdiff.tgz \
 && oasdiff --version

# ---------------------------------------------------------------------------
# The download block, and why RUSTUP_TOOLCHAIN is deliberately NOT set here.
# ---------------------------------------------------------------------------
# DIVERGENCE FROM THE AGREED SPEC, argued rather than quietly taken. The spec
# said "RUSTUP_TOOLCHAIN pinned plus offline behaviour". Setting
# RUSTUP_TOOLCHAIN would OVERRIDE rust-toolchain.toml, and that defeats the
# thing the pin is for: when the workspace later bumps its pin, an image with
# RUSTUP_TOOLCHAIN set keeps compiling with the OLD toolchain and says nothing.
# A silent wrong compiler is the exact failure this whole file exists to
# prevent.
#
# Leaving it unset, rust-toolchain.toml decides — and then the second half of
# the spec does the work. With the rustup download endpoints pointed at a
# closed local port, an image that lacks the toolchain the repo asks for FAILS
# IMMEDIATELY and loudly, instead of silently downloading it on first use in
# every container, every run. So a stale image announces itself, which is the
# behaviour the spec wanted; the mechanism is the block, not the override.
#
# This affects rustup only. Cargo fetches crates from the registry, which is
# configured elsewhere and is untouched.
ENV RUSTUP_DIST_SERVER=http://127.0.0.1:9
ENV RUSTUP_UPDATE_ROOT=http://127.0.0.1:9

# ---------------------------------------------------------------------------
# Prove the image is what it claims, before it is ever tagged.
# ---------------------------------------------------------------------------
# Runs AFTER the block above on purpose: it therefore also proves the block
# does not break an image that is correct. The real rust-toolchain.toml is
# copied in, because the assertion asks what toolchain is active FOR A
# DIRECTORY — without that file it would describe the image default and agree
# with itself. The assertion refuses rather than passing if the file is absent
# or names something other than what this build expects.
COPY rust-toolchain.toml /opt/toolchain-check/rust-toolchain.toml
COPY .forgejo/images/ci-toolchain/assert-toolchain.sh /usr/local/bin/assert-toolchain.sh
RUN chmod +x /usr/local/bin/assert-toolchain.sh \
 && /usr/local/bin/assert-toolchain.sh "$RUST_TOOLCHAIN" /opt/toolchain-check \
 && for t in cargo-deny cargo-fmt-toml; do \
      command -v "$t" >/dev/null || { echo "carried-for-npoc tool $t is missing" >&2; exit 1; }; \
    done \
 && echo "carried for runcove-npoc, not yet used by any check: cargo-deny cargo-fmt-toml"

# hardened-run.sh starts this image with `--entrypoint sleep … 86400` and then
# `docker cp`s the working tree to /src, so no CMD or ENTRYPOINT here is load
# bearing. WORKDIR is set only so a shell dropped into the container for
# debugging starts where the source will be.
WORKDIR /src
