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
    /// (directories `& 0o750`, files `& 0o640`, and created at those modes) instead
    /// of being set to exactly 0o700 / 0o600, so a reader keeps the read access a
    /// default POSIX ACL on the recordings root gives it. Every access beyond the
    /// owner comes from the ACL: `warpgate run` refuses to start unless the umask
    /// covers 0o077 (see [`Self::check_umask_for_recordings`]). A plain group grant on
    /// the root does not work: setgid is stripped, so new files get Warpgate's primary
    /// group. Only takes effect while [`Self::should_secure_files`] is true, and only
    /// for the recordings tree.
    pub const fn recordings_keep_group_read(&self) -> bool {
        self.recordings_keep_group_read
    }

    /// With [`Self::recordings_keep_group_read`] in effect, an error unless the
    /// process umask covers 0o077, so nothing a default ACL does not grant is opened
    /// up. Always `Ok` otherwise.
    pub fn check_umask_for_recordings(&self) -> anyhow::Result<()> {
        if !(self.should_secure_files && self.recordings_keep_group_read) {
            return Ok(());
        }
        let umask = crate::helpers::fs::process_umask()
            .context("--recordings-keep-group-read needs the process umask, which could not be read. Refusing to start")?;
        crate::helpers::fs::check_umask_covers(
            umask,
            crate::helpers::fs::UMASK_REQUIRED_TO_KEEP_GROUP_READ,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(secure: bool, keep_group_read: bool) -> GlobalParams {
        GlobalParams::new(PathBuf::from("/etc/warpgate.yaml"), secure)
            .unwrap()
            .with_recordings_keep_group_read(keep_group_read)
    }

    /// With the flag on, a umask that leaves any group or other bit refuses the start;
    /// run this under umask 0022 and 0077 to see both sides.
    #[test]
    fn the_umask_is_checked_only_with_the_flag() {
        let umask = crate::helpers::fs::process_umask().unwrap();
        let result = params(true, true).check_umask_for_recordings();
        if umask & 0o077 == 0o077 {
            result.unwrap();
        } else {
            let message = result.unwrap_err().to_string();
            assert!(message.contains("Refusing to start"), "{message}");
        }
        params(true, false).check_umask_for_recordings().unwrap();
        params(false, true).check_umask_for_recordings().unwrap();
        params(false, false).check_umask_for_recordings().unwrap();
    }
}
