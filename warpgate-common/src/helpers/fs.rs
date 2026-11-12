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

/// What a recordings directory keeps under `--recordings-keep-group-read`: at most
/// owner rwx and group r-x. Everything else (setuid/setgid/sticky, group write, all
/// "other" bits) is stripped. Under a POSIX ACL the group bits are the ACL mask, so
/// what they keep is the most the ACL's named entries and owning-group entry may
/// grant; every access beyond the owner comes from the ACL. Recordings directories
/// are also created with this mode.
pub const KEEP_FOR_DIRECTORY: u32 = 0o750;

/// What a recording file keeps under `--recordings-keep-group-read`: at most owner rw
/// and group r. Everything else (exec bits, setuid/setgid/sticky, group write, all
/// "other" bits) is stripped. Under a POSIX ACL the group bits are the ACL mask, as
/// for [`KEEP_FOR_DIRECTORY`]. Recording files are also created with this mode.
pub const KEEP_FOR_RECORDING_FILE: u32 = 0o640;

/// The bits the process umask must clear for `--recordings-keep-group-read`: every
/// group and other bit, so a new recording gets no access beyond the owner except
/// what a default ACL grants (where one applies, the kernel uses it in place of the
/// umask).
pub const UMASK_REQUIRED_TO_KEEP_GROUP_READ: u32 = 0o077;

/// This process's umask, read from `/proc/self/status`. Reading it through `umask(2)`
/// would set it too, for every thread of the process.
pub fn process_umask() -> std::io::Result<u32> {
    parse_umask_from_status(&std::fs::read_to_string("/proc/self/status")?).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "/proc/self/status has no Umask line",
        )
    })
}

fn parse_umask_from_status(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
}

/// An error unless `umask` clears every bit of `required`.
pub fn check_umask_covers(umask: u32, required: u32) -> anyhow::Result<()> {
    if umask & required != required {
        anyhow::bail!(
            "--recordings-keep-group-read needs a umask that covers {required:04o} (for example UMask=0077 in the service unit); this process runs with umask {umask:04o}. Refusing to start"
        );
    }
    Ok(())
}

/// Opens a recording file the way `--recordings-keep-group-read` needs: created at
/// most [`KEEP_FOR_RECORDING_FILE`], so it is never born wider, even under a default
/// ACL, and never through a symlink in place of the file (`O_NOFOLLOW`: the open
/// fails with `ELOOP`, and the recording start with it).
pub fn restrict_recording_file_open(
    options: &mut tokio::fs::OpenOptions,
) -> &mut tokio::fs::OpenOptions {
    options
        .mode(KEEP_FOR_RECORDING_FILE)
        .custom_flags(nix::libc::O_NOFOLLOW)
}

/// Creates a recordings directory and any missing parent the way
/// `--recordings-keep-group-read` needs: each one created at most
/// [`KEEP_FOR_DIRECTORY`], so it is never born wider, even under a default ACL.
/// Existing directories are left as they are.
pub async fn create_recording_directory_all(path: &Path) -> std::io::Result<()> {
    tokio::fs::DirBuilder::new()
        .recursive(true)
        .mode(KEEP_FOR_DIRECTORY)
        .create(path)
        .await
}

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

fn not_owned(path: &Path, owner: u32, euid: u32) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "cannot tighten permissions of {}: it is owned by uid {owner}, not by this process (uid {euid})",
            path.display()
        ),
    )
}

/// Tightens a directory Warpgate created to `current & keep` instead of setting an
/// exact mode. It never adds a bit, so a reader granted read by a default POSIX ACL
/// keeps it (an exact `chmod 0700` would also zero the ACL mask). A symlink at `path`,
/// a directory owned by another user (unless this process runs as root) and any chmod
/// failure are errors: the caller fails closed.
pub fn secure_directory_by_masking<P: AsRef<Path>>(path: P, keep: u32) -> std::io::Result<()> {
    let path = path.as_ref();
    let dir = open_directory_no_follow(path)?;
    match mask_fd(dir.as_fd(), keep, true)? {
        Masked::Done => Ok(()),
        Masked::NotOwned { owner, euid } => Err(not_owned(path, owner, euid)),
    }
}

/// Tightens an already-open file Warpgate created to `current & keep`, through its
/// descriptor. A file owned by another user (unless this process runs as root) and
/// any chmod failure are errors: the caller fails closed. `path` is only for the
/// error. Open the file with [`restrict_recording_file_open`] so a symlink in its
/// place fails the open.
pub fn secure_open_file_by_masking(file: impl AsFd, keep: u32, path: &Path) -> std::io::Result<()> {
    match mask_fd(file.as_fd(), keep, true)? {
        Masked::Done => Ok(()),
        Masked::NotOwned { owner, euid } => Err(not_owned(path, owner, euid)),
    }
}

/// Which warnings about the recordings root have been logged already.
struct RootWarnings {
    not_owned: AtomicBool,
    failed: AtomicBool,
}

static ROOT_WARNINGS: RootWarnings = RootWarnings {
    not_owned: AtomicBool::new(false),
    failed: AtomicBool::new(false),
};

/// Tightens the recordings root to `current & keep`. The root may predate Warpgate
/// and belong to someone else, so this never fails: a root this process does not own
/// is left alone even when running as root, and a root that cannot be opened (for
/// example a symlink) or chmodded is left as it is. Each case is logged once per
/// process, not once per recording.
pub fn secure_recordings_root_by_masking<P: AsRef<Path>>(path: P, keep: u32) {
    secure_recordings_root_warning_once(path.as_ref(), keep, &ROOT_WARNINGS);
}

fn secure_recordings_root_warning_once(path: &Path, keep: u32, warnings: &RootWarnings) {
    let result = open_directory_no_follow(path).and_then(|dir| mask_fd(dir.as_fd(), keep, false));
    match result {
        Ok(Masked::Done) => {}
        Ok(Masked::NotOwned { owner, euid }) => {
            if !warnings.not_owned.swap(true, Ordering::Relaxed) {
                warn!(
                    "Recordings root {path:?} is owned by uid {owner}, not by this process (uid {euid}): leaving its mode as it is. Its owner must keep it closed to others and give the reader access to it"
                );
            }
        }
        Err(e) => {
            if !warnings.failed.swap(true, Ordering::Relaxed) {
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

    /// A directory and a file this process does not own, or `None` (for example when
    /// running as root, who owns them all and may chmod them anyway).
    fn not_owned_dir_and_file() -> Option<(&'static Path, &'static Path)> {
        let euid = nix::unistd::geteuid();
        if euid.is_root() {
            return None;
        }
        let not_mine =
            |p: &&'static Path| std::fs::metadata(p).is_ok_and(|m| m.uid() != euid.as_raw());
        let dir = ["/usr", "/etc", "/"]
            .into_iter()
            .map(Path::new)
            .find(not_mine)?;
        let file = ["/etc/passwd", "/etc/hostname", "/etc/os-release"]
            .into_iter()
            .map(Path::new)
            .find(|p| not_mine(p) && std::fs::File::open(p).is_ok())?;
        Some((dir, file))
    }

    /// A session or recording directory, or a recording file, that is not this
    /// process's own fails closed: an error, and no chmod is attempted.
    #[test]
    fn a_child_owned_by_someone_else_is_an_error() {
        let Some((dir, file)) = not_owned_dir_and_file() else {
            eprintln!("skipped: no directory and file owned by another user");
            return;
        };
        let (dir_before, file_before) = (mode(dir), mode(file));

        let err = secure_directory_by_masking(dir, KEEP_FOR_DIRECTORY).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("owned by uid"), "{err}");

        let open = std::fs::File::open(file).unwrap();
        let err = secure_open_file_by_masking(&open, KEEP_FOR_RECORDING_FILE, file).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");

        assert_eq!(mode(dir), dir_before);
        assert_eq!(mode(file), file_before);
    }

    async fn open_recording_file(path: &Path) -> std::io::Result<tokio::fs::File> {
        let mut options = tokio::fs::File::options();
        options.append(true).create(true);
        restrict_recording_file_open(&mut options).open(path).await
    }

    /// A symlink in place of a recording file fails the open; its target is untouched.
    #[tokio::test]
    async fn a_symlinked_recording_file_is_refused() {
        let (tmp, _dir, file) = dir_and_file(0o700, 0o666);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();

        let err = open_recording_file(&link).await.unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::libc::ELOOP), "{err}");
        assert_eq!(mode(&file), 0o666);
        assert_eq!(std::fs::read(&file).unwrap(), b"x");
    }

    /// New directories and files are created at most 0o750 / 0o640: what the umask
    /// leaves of those, whatever it is.
    #[tokio::test]
    async fn recordings_are_created_at_the_ceiling() {
        let umask = process_umask().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("root");
        let leaf = parent.join("session").join("recording");
        create_recording_directory_all(&leaf).await.unwrap();
        for dir in [&parent, &parent.join("session"), &leaf] {
            assert_eq!(mode(dir), 0o750 & !umask, "{}", dir.display());
        }

        let file = leaf.join("data.ndjson");
        drop(open_recording_file(&file).await.unwrap());
        assert_eq!(mode(&file), 0o640 & !umask);

        // An existing file is opened as it is, for appending.
        set(&file, 0o600);
        drop(open_recording_file(&file).await.unwrap());
        assert_eq!(mode(&file), 0o600);
    }

    #[test]
    fn the_umask_must_cover_group_and_other() {
        for wide in [0o000, 0o002, 0o022, 0o027, 0o070, 0o007] {
            let err = check_umask_covers(wide, UMASK_REQUIRED_TO_KEEP_GROUP_READ).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("covers 0077"), "{message}");
            assert!(message.contains(&format!("umask {wide:04o}")), "{message}");
        }
        for narrow in [0o077, 0o177, 0o277, 0o777] {
            check_umask_covers(narrow, UMASK_REQUIRED_TO_KEEP_GROUP_READ).unwrap();
        }
    }

    #[test]
    fn the_umask_is_parsed_from_proc_status() {
        assert_eq!(
            parse_umask_from_status("Name:\twarpgate\nUmask:\t0077\nState:\tR\n"),
            Some(0o077)
        );
        assert_eq!(parse_umask_from_status("Umask:\t0022\n"), Some(0o022));
        assert_eq!(parse_umask_from_status("Name:\twarpgate\n"), None);
    }

    /// The umask read without changing it is the one a child process inherits.
    #[test]
    fn the_process_umask_is_read_without_changing_it() {
        let Ok(output) = std::process::Command::new("sh")
            .args(["-c", "umask"])
            .output()
        else {
            eprintln!("skipped: no sh");
            return;
        };
        let shell = u32::from_str_radix(String::from_utf8_lossy(&output.stdout).trim(), 8).unwrap();
        assert_eq!(process_umask().unwrap(), shell);
        assert_eq!(process_umask().unwrap(), shell);
    }

    /// Counts the warnings logged on this thread.
    struct CountWarnings(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl tracing::Subscriber for CountWarnings {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn warnings_logged(f: impl FnOnce()) -> usize {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tracing::subscriber::with_default(CountWarnings(count.clone()), f);
        count.load(Ordering::Relaxed)
    }

    fn fresh_warnings() -> RootWarnings {
        RootWarnings {
            not_owned: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }
    }

    /// A root that cannot be secured is warned about once, not once per recording.
    #[test]
    fn a_root_problem_is_warned_about_once() {
        let (tmp, dir, _file) = dir_and_file(0o777, 0o666);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let warnings = fresh_warnings();
        let logged = warnings_logged(|| {
            for _ in 0..3 {
                secure_recordings_root_warning_once(&link, KEEP_FOR_DIRECTORY, &warnings);
            }
        });
        assert_eq!(logged, 1);

        let Some((other, _)) = not_owned_dir_and_file() else {
            eprintln!("skipped the not-owned half: no directory owned by another user");
            return;
        };
        let logged = warnings_logged(|| {
            for _ in 0..3 {
                secure_recordings_root_warning_once(other, KEEP_FOR_DIRECTORY, &warnings);
            }
        });
        assert_eq!(logged, 1);
    }
}
