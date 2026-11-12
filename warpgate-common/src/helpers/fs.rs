use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{error, warn};

fn maybe_apply_permissions<P: AsRef<Path>>(
    path: P,
    permissions: std::fs::Permissions,
) -> std::io::Result<()> {
    let metadata = std::fs::metadata(&path)?;
    let current = metadata.permissions();
    if (current.mode() & 0o777) != permissions.mode() {
        let uid = nix::unistd::geteuid();
        if uid.is_root() || metadata.uid() == uid.as_raw() {
            std::fs::set_permissions(path, permissions)?;
        } else {
            error!(
                "Warning: cannot tighten file permissions for {:?}",
                path.as_ref()
            );
            warn_notice();
        }
    }
    Ok(())
}

fn warn_failure(e: &std::io::Error) {
    error!("Warning: failed to tighten file permissions: {e}");
    warn_notice();
}

fn warn_notice() {
    error!(
        "If you are managing file permissions externally and do not need Warpgate to change them, you can pass --skip-securing-files"
    );
}

pub fn secure_directory<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o700))
        .inspect_err(warn_failure)
}

pub fn secure_file<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    maybe_apply_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))
        .inspect_err(warn_failure)
}

/// What a recordings directory keeps when a separate reader is granted read access:
/// owner rwx and group r-x. Everything else (setuid/setgid/sticky, group write, all
/// "other" bits) is stripped.
pub const KEEP_FOR_DIRECTORY: u32 = 0o750;

/// What a recording file keeps when a separate reader is granted read access: owner
/// rw and group r. Everything else (exec bits, setuid/setgid/sticky, group write, all
/// "other" bits) is stripped.
pub const KEEP_FOR_RECORDING_FILE: u32 = 0o640;

enum Masked {
    Done,
    NotOwned { owner: u32, euid: u32 },
}

/// Clears the bits outside `keep` (`current & keep`) on an open file or directory,
/// through its descriptor (fstat + fchmod), so the object checked is the object
/// changed. It never adds a bit. With `root_overrides`, a process running as root
/// masks an object it does not own (like [`secure_directory`] does).
fn mask_fd(fd: BorrowedFd<'_>, keep: u32, root_overrides: bool) -> std::io::Result<Masked> {
    let file = std::fs::File::from(fd.try_clone_to_owned()?);
    let metadata = file.metadata()?;
    let euid = nix::unistd::geteuid();
    if metadata.uid() != euid.as_raw() && !(root_overrides && euid.is_root()) {
        return Ok(Masked::NotOwned {
            owner: metadata.uid(),
            euid: euid.as_raw(),
        });
    }
    let current = metadata.permissions().mode() & 0o7777;
    let target = current & keep;
    if current != target {
        file.set_permissions(std::fs::Permissions::from_mode(target))?;
    }
    Ok(Masked::Done)
}

/// Opens a directory without following a symlink in its last component
/// (`O_DIRECTORY | O_NOFOLLOW`), so a symlink swapped in there is refused (`ENOTDIR`
/// on Linux, `ELOOP` on some systems) rather than chmodded through. Earlier components are still resolved normally.
fn open_directory_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(path)
}

fn log_not_owned(path: &Path, owner: u32, euid: u32) {
    error!(
        "Warning: cannot tighten permissions of {path:?}: it is owned by uid {owner}, not by this process (uid {euid})"
    );
}

/// Tightens a directory Warpgate created to `current & keep` instead of setting an
/// exact mode. It never adds a bit, so a reader granted read by a default POSIX ACL
/// keeps it (an exact `chmod 0700` would also zero the ACL mask). A symlink at `path`
/// and any chmod failure are errors: the caller fails closed.
pub fn secure_directory_by_masking<P: AsRef<Path>>(path: P, keep: u32) -> std::io::Result<()> {
    let path = path.as_ref();
    let dir = open_directory_no_follow(path)?;
    if let Masked::NotOwned { owner, euid } = mask_fd(dir.as_fd(), keep, true)? {
        log_not_owned(path, owner, euid);
    }
    Ok(())
}

/// Tightens an already-open file Warpgate created to `current & keep`, through its
/// descriptor. Same rules as [`secure_directory_by_masking`]; `path` is only for logs.
pub fn secure_open_file_by_masking(file: impl AsFd, keep: u32, path: &Path) -> std::io::Result<()> {
    if let Masked::NotOwned { owner, euid } = mask_fd(file.as_fd(), keep, true)? {
        log_not_owned(path, owner, euid);
    }
    Ok(())
}

static ROOT_NOT_OWNED_WARNED: AtomicBool = AtomicBool::new(false);
static ROOT_FAILED_WARNED: AtomicBool = AtomicBool::new(false);

/// Tightens the recordings root to `current & keep`. The root may predate Warpgate
/// and belong to someone else, so this never fails: a root this process does not own
/// is left alone even when running as root, and a root that cannot be opened (for
/// example a symlink) or chmodded is left as it is. Each case is logged once per
/// process, not once per recording.
pub fn secure_recordings_root_by_masking<P: AsRef<Path>>(path: P, keep: u32) {
    let path = path.as_ref();
    let result = open_directory_no_follow(path).and_then(|dir| mask_fd(dir.as_fd(), keep, false));
    match result {
        Ok(Masked::Done) => {}
        Ok(Masked::NotOwned { owner, euid }) => {
            if !ROOT_NOT_OWNED_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    "Recordings root {path:?} is owned by uid {owner}, not by this process (uid {euid}): leaving its mode as it is. Its owner must keep it closed to others and give the reader access to it"
                );
            }
        }
        Err(e) => {
            if !ROOT_FAILED_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    "Could not tighten the recordings root {path:?} ({e}): leaving its mode as it is"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    fn set(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn dir_and_file(initial_dir: u32, initial_file: u32) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        let file = tmp.path().join("f");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(&file, b"x").unwrap();
        set(&dir, initial_dir);
        set(&file, initial_file);
        (tmp, dir, file)
    }

    /// Masks the file through a descriptor opened before its mode was set, so even a
    /// mode that forbids opening it is masked.
    fn mask_file(file: &Path) {
        let mode_before = mode(file);
        set(file, 0o600);
        let open = std::fs::File::open(file).unwrap();
        set(file, mode_before);
        secure_open_file_by_masking(&open, KEEP_FOR_RECORDING_FILE, file).unwrap();
    }

    fn mask(dir: &Path, file: &Path) {
        secure_directory_by_masking(dir, KEEP_FOR_DIRECTORY).unwrap();
        mask_file(file);
    }

    #[test]
    fn exact_helpers_keep_their_modes() {
        let (_tmp, dir, file) = dir_and_file(0o755, 0o644);
        secure_directory(&dir).unwrap();
        secure_file(&file).unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&file), 0o600);
    }

    #[test]
    fn masking_leaves_group_read_alone() {
        let (_tmp, dir, file) = dir_and_file(0o750, 0o640);
        mask(&dir, &file);
        assert_eq!(mode(&dir), 0o750);
        assert_eq!(mode(&file), 0o640);
    }

    #[test]
    fn masking_strips_group_write_and_other() {
        let (_tmp, dir, file) = dir_and_file(0o777, 0o666);
        mask(&dir, &file);
        assert_eq!(mode(&dir), 0o750);
        assert_eq!(mode(&file), 0o640);
    }

    #[test]
    fn masking_strips_special_and_exec_bits_down_to_the_ceiling() {
        let (_tmp, dir, file) = dir_and_file(0o7777, 0o7777);
        mask(&dir, &file);
        assert_eq!(mode(&dir), 0o750);
        assert_eq!(mode(&file), 0o640);
    }

    #[test]
    fn masking_never_adds_a_bit() {
        // A directory must be readable to be opened, so 0o000 is only tried on the file.
        for (d, f) in [(0o700, 0o600), (0o500, 0o400), (0o700, 0o000)] {
            let (_tmp, dir, file) = dir_and_file(d, f);
            mask(&dir, &file);
            assert_eq!(mode(&dir), d);
            assert_eq!(mode(&file), f);
        }
    }

    #[test]
    fn masking_an_executable_file_drops_every_exec_bit() {
        let (_tmp, _dir, file) = dir_and_file(0o700, 0o755);
        mask_file(&file);
        assert_eq!(mode(&file), 0o640);
    }

    /// The fd is what gets masked: a path swapped after the open is not touched.
    #[test]
    fn masking_an_open_file_changes_the_opened_file_not_the_path() {
        let (tmp, _dir, file) = dir_and_file(0o700, 0o666);
        let open = std::fs::File::open(&file).unwrap();
        let moved = tmp.path().join("moved");
        std::fs::rename(&file, &moved).unwrap();
        std::fs::write(&file, b"y").unwrap();
        set(&file, 0o666);

        secure_open_file_by_masking(&open, KEEP_FOR_RECORDING_FILE, &file).unwrap();
        assert_eq!(mode(&moved), 0o640);
        assert_eq!(mode(&file), 0o666);
    }

    #[test]
    fn a_symlinked_directory_is_refused_not_followed() {
        let (tmp, dir, _file) = dir_and_file(0o777, 0o666);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();

        let err = secure_directory_by_masking(&link, KEEP_FOR_DIRECTORY).unwrap_err();
        // Linux reports ENOTDIR (O_DIRECTORY sees the link itself); ELOOP is the
        // O_NOFOLLOW error elsewhere. Either way the open is refused.
        assert!(
            matches!(
                err.raw_os_error(),
                Some(nix::libc::ENOTDIR | nix::libc::ELOOP)
            ),
            "{err}"
        );
        assert_eq!(mode(&dir), 0o777);
    }

    #[test]
    fn a_file_is_not_a_directory() {
        let (_tmp, _dir, file) = dir_and_file(0o700, 0o666);
        let err = secure_directory_by_masking(&file, KEEP_FOR_DIRECTORY).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::libc::ENOTDIR));
        assert_eq!(mode(&file), 0o666);
    }

    #[test]
    fn the_root_is_masked_when_owned() {
        let (_tmp, dir, _file) = dir_and_file(0o777, 0o666);
        secure_recordings_root_by_masking(&dir, KEEP_FOR_DIRECTORY);
        assert_eq!(mode(&dir), 0o750);
    }

    /// A root that cannot be opened is left alone, and is not an error.
    #[test]
    fn a_symlinked_root_is_left_alone_without_failing() {
        let (tmp, dir, _file) = dir_and_file(0o777, 0o666);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        secure_recordings_root_by_masking(&link, KEEP_FOR_DIRECTORY);
        assert_eq!(mode(&dir), 0o777);
    }

    /// A root owned by another user is left alone, and is not an error. Needs a
    /// directory this process does not own; skipped when none is found (for example
    /// when running as root, who owns them all).
    #[test]
    fn a_root_owned_by_someone_else_is_left_alone_without_failing() {
        let euid = nix::unistd::geteuid().as_raw();
        let Some(other) = ["/", "/usr", "/etc"]
            .into_iter()
            .map(Path::new)
            .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_dir() && m.uid() != euid))
        else {
            eprintln!("skipped: no directory owned by another user");
            return;
        };
        // Skipped for ownership, not merely failed: the chmod is never attempted.
        let dir = open_directory_no_follow(other).unwrap();
        assert!(matches!(
            mask_fd(dir.as_fd(), KEEP_FOR_DIRECTORY, false).unwrap(),
            Masked::NotOwned { .. }
        ));
        let before = mode(other);
        secure_recordings_root_by_masking(other, KEEP_FOR_DIRECTORY);
        assert_eq!(mode(other), before);
    }
}
