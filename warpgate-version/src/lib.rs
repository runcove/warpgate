//! The Warpgate version string, set ONCE at startup by the binary that runs.
//!
//! The git-describe string is computed by `git_version!` in each binary's
//! `main.rs`, never in a library crate. A library that embedded it changed on
//! every commit, and so did every crate compiled against it -- a new commit
//! recompiled the admin API and the HTTP proxy even when neither had changed.
//! Libraries read the string at run time through `warpgate_version()`.

use std::sync::OnceLock;

static VERSION: OnceLock<&'static str> = OnceLock::new();

/// Record the version. Call once, first thing in `main`; later calls are
/// ignored so the first value always wins.
pub fn set_warpgate_version(version: &'static str) {
    let _ = VERSION.set(version);
}

/// The version recorded at startup, or "unknown" if no binary recorded one
/// (unit tests, for instance).
pub fn warpgate_version() -> &'static str {
    VERSION.get().copied().unwrap_or("unknown")
}

/// Expands to the git-describe string of the tree being compiled. Used only in
/// binaries: `set_warpgate_version(git_describe!())`.
#[macro_export]
macro_rules! git_describe {
    () => {
        $crate::__git_version::git_version!(
            args = ["--tags", "--always", "--dirty=-modified", "--match", "v[0-9]*"],
            fallback = "unknown"
        )
    };
}

#[doc(hidden)]
pub use git_version as __git_version;
