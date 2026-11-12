use std::path::PathBuf;

use anyhow::Context;

#[derive(Clone)]
pub struct GlobalParams {
    config_path: PathBuf,
    should_secure_files: bool,
    recordings_keep_group_read: bool,
    paths_relative_to: PathBuf,
}

impl GlobalParams {
    pub fn new(config_path: PathBuf, should_secure_files: bool) -> anyhow::Result<Self> {
        Ok(Self {
            paths_relative_to: config_path
                .parent()
                .context("Failed to determine config parent directory")?
                .to_path_buf(),
            config_path,
            should_secure_files,
            recordings_keep_group_read: false,
        })
    }

    /// Opt in to subtract-only securing of the recordings tree (see [`Self::recordings_keep_group_read`]).
    #[must_use]
    pub const fn with_recordings_keep_group_read(mut self, enabled: bool) -> Self {
        self.recordings_keep_group_read = enabled;
        self
    }

    pub const fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    pub const fn paths_relative_to(&self) -> &PathBuf {
        &self.paths_relative_to
    }

    pub const fn should_secure_files(&self) -> bool {
        self.should_secure_files
    }

    /// Whether the recordings directories and files are secured by removing bits
    /// (directories `& 0o750`, files `& 0o640`) instead of being set to exactly
    /// 0o700 / 0o600, so a reader keeps the read access a default POSIX ACL on the
    /// recordings root gives it (or a group Warpgate's own user is in, with a umask
    /// that leaves group read). A plain group grant on the root does not work: setgid
    /// is stripped, so new files get Warpgate's primary group. Only takes effect while
    /// [`Self::should_secure_files`] is true, and only for the recordings tree.
    pub const fn recordings_keep_group_read(&self) -> bool {
        self.recordings_keep_group_read
    }
}
