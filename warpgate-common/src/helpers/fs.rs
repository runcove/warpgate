use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::prelude::PermissionsExt;
use std::path::{Component, Path};
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

/// The bits of `mode` as a [`nix::sys::stat::Mode`].
const fn nix_mode(mode: u32) -> nix::sys::stat::Mode {
    nix::sys::stat::Mode::from_bits_truncate(mode as nix::libc::mode_t)
}

/// Makes directory `name` in `dir` at most [`KEEP_FOR_DIRECTORY`] (`mkdirat`). An
/// existing entry of that name, whatever it is, is left alone: opening it decides.
fn make_directory_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<()> {
    match nix::sys::stat::mkdirat(dir, name, nix_mode(KEEP_FOR_DIRECTORY)) {
        Ok(()) | Err(nix::errno::Errno::EEXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Opens directory `name` in `dir` (`openat`), never following a symlink there.
fn open_directory_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<OwnedFd> {
    use nix::fcntl::OFlag;
    Ok(nix::fcntl::openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?)
}

/// Opens file `name` in `dir` for appending (`openat`), creating it at most
/// [`KEEP_FOR_RECORDING_FILE`], never through a symlink there (`O_NOFOLLOW`: `ELOOP`).
fn open_file_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<std::fs::File> {
    use nix::fcntl::OFlag;
    let fd = nix::fcntl::openat(
        dir,
        name,
        OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        nix_mode(KEEP_FOR_RECORDING_FILE),
    )?;
    Ok(std::fs::File::from(fd))
}

/// The components of `relative`, each a plain name. An absolute path, `.` or `..`
/// is refused, so a walk never leaves the directory it starts from.
fn plain_names(relative: &Path) -> std::io::Result<Vec<&OsStr>> {
    relative
        .components()
        .map(|c| match c {
            Component::Normal(name) => Ok(name),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a plain relative path", relative.display()),
            )),
        })
        .collect()
}

/// Walks `names` down from `root`, each directory opened relative to the one above
/// it and never through a symlink, so the directory checked is the directory used
/// and a symlink swapped in anywhere below the root is refused, not followed. With
/// `create`, a missing directory is made at most [`KEEP_FOR_DIRECTORY`] first. Each
/// directory is tightened to `current & KEEP_FOR_DIRECTORY` through its descriptor; a
/// directory owned by another user (unless this process runs as root) and any chmod
/// failure are errors, so the caller fails closed. The root itself is opened by path
/// and only to walk from (`O_PATH` on Linux): it is never chmodded here, so a root
/// this process can write and search but not read still works. Returns the last
/// directory.
fn walk_masking(root: &Path, names: &[&OsStr], create: bool) -> std::io::Result<OwnedFd> {
    let mut path = root.to_path_buf();
    let mut current = OwnedFd::from(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(ROOT_WALK_FLAGS)
            .open(root)?,
    );
    for name in names {
        path.push(name);
        if create {
            make_directory_at(current.as_fd(), name)?;
        }
        let next = open_directory_at(current.as_fd(), name)?;
        if let Masked::NotOwned { owner, euid } = mask_fd(next.as_fd(), KEEP_FOR_DIRECTORY, true)? {
            return Err(not_owned(&path, owner, euid));
        }
        current = next;
    }
    Ok(current)
}

/// How [`walk_masking`] opens the root: as a directory to walk from, not to read
/// (`O_PATH` ignores the access mode, so the read asked for is never checked).
#[cfg(any(target_os = "linux", target_os = "android"))]
const ROOT_WALK_FLAGS: i32 = nix::libc::O_PATH | nix::libc::O_DIRECTORY;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const ROOT_WALK_FLAGS: i32 = nix::libc::O_DIRECTORY;

/// Creates the directories of `relative` beneath the recordings `root` the way
/// `--recordings-keep-group-read` needs: the root, if missing, by path; below it
/// each directory relative to the one above (`mkdirat`, then `openat` with
/// `O_NOFOLLOW`), so nothing is created or chmodded through a symlink below the
/// root. New directories are created at most [`KEEP_FOR_DIRECTORY`]; every directory
/// below the root is then tightened to `current & KEEP_FOR_DIRECTORY` and fails
/// closed as [`walk_masking`] describes. The root is not tightened here.
pub fn create_recording_directories(root: &Path, relative: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(KEEP_FOR_DIRECTORY)
        .create(root)?;
    walk_masking(root, &plain_names(relative)?, true).map(drop)
}

/// Opens the recording file at `relative` beneath the recordings `root` for
/// appending, the way `--recordings-keep-group-read` needs: every directory below
/// the root opened relative to the one above and never through a symlink, each
/// tightened as by [`create_recording_directories`] (none is created); the file
/// opened the same way (`O_NOFOLLOW`: a symlink there fails with `ELOOP`), created
/// at most [`KEEP_FOR_RECORDING_FILE`] and then tightened to
/// `current & KEEP_FOR_RECORDING_FILE`, failing closed like
/// [`secure_open_file_by_masking`].
pub fn open_recording_file(root: &Path, relative: &Path) -> std::io::Result<std::fs::File> {
    let names = plain_names(relative)?;
    let Some((file_name, dirs)) = names.split_last() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a recording file needs a name",
        ));
    };
    let dir = walk_masking(root, dirs, false)?;
    let file = open_file_at(dir.as_fd(), file_name)?;
    secure_open_file_by_masking(&file, KEEP_FOR_RECORDING_FILE, &root.join(relative))?;
    Ok(file)
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

/// Tightens an already-open file Warpgate created to `current & keep`, through its
/// descriptor. A file owned by another user (unless this process runs as root) and
/// any chmod failure are errors: the caller fails closed. `path` is only for the
/// error. [`open_recording_file`] opens a recording file this way.
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

    /// Walks to `dir` from its parent the way a recording is opened: `dir` opened
    /// with `openat` relative to its parent and tightened by [`walk_masking`].
    fn walk_to(dir: &Path) -> std::io::Result<OwnedFd> {
        let (parent, name) = (dir.parent().unwrap(), dir.file_name().unwrap());
        walk_masking(parent, &[name], false)
    }

    fn mask(dir: &Path, file: &Path) {
        walk_to(dir).unwrap();
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

        let err = walk_to(&link).unwrap_err();
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
        let err = walk_to(&file).unwrap_err();
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

    /// A root owned by another user is left alone, and is not an error, even when
    /// running as root.
    #[test]
    fn a_root_owned_by_someone_else_is_left_alone_without_failing() {
        let other = not_owned_dir_and_file();
        // Skipped for ownership, not merely failed: the chmod is never attempted.
        let dir = open_directory_no_follow(&other.dir).unwrap();
        assert!(matches!(
            mask_fd(dir.as_fd(), KEEP_FOR_DIRECTORY, false).unwrap(),
            Masked::NotOwned { .. }
        ));
        let before = mode(&other.dir);
        secure_recordings_root_by_masking(&other.dir, KEEP_FOR_DIRECTORY);
        assert_eq!(mode(&other.dir), before);
    }

    /// The uid and gid given to the test's objects when running as root (`nobody`).
    const OTHER_ID: u32 = 65534;

    /// A directory and a file this process does not own. As a user, system paths
    /// owned by root. As root, who owns those, a fresh directory (mode 0777) and file
    /// (mode 0666) chowned to uid and gid 65534; `_tmp` keeps them alive.
    struct NotOwnedPaths {
        _tmp: Option<tempfile::TempDir>,
        dir: PathBuf,
        file: PathBuf,
        as_root: bool,
    }

    fn not_owned_dir_and_file() -> NotOwnedPaths {
        let euid = nix::unistd::geteuid();
        if euid.is_root() {
            let (tmp, dir, file) = dir_and_file(0o777, 0o666);
            std::os::unix::fs::chown(&dir, Some(OTHER_ID), Some(OTHER_ID)).unwrap();
            std::os::unix::fs::chown(&file, Some(OTHER_ID), Some(OTHER_ID)).unwrap();
            return NotOwnedPaths {
                _tmp: Some(tmp),
                dir,
                file,
                as_root: true,
            };
        }
        let not_mine =
            |p: &&'static Path| std::fs::metadata(p).is_ok_and(|m| m.uid() != euid.as_raw());
        // Not `/`: a walk reaches a directory as a child of another.
        let dir = ["/usr", "/etc", "/var"]
            .into_iter()
            .map(Path::new)
            .find(|p| not_mine(p) && p.is_dir())
            .expect("a directory owned by another user");
        let file = ["/etc/passwd", "/etc/hostname", "/etc/os-release"]
            .into_iter()
            .map(Path::new)
            .find(|p| not_mine(p) && std::fs::File::open(p).is_ok())
            .expect("a readable file owned by another user");
        NotOwnedPaths {
            _tmp: None,
            dir: dir.to_path_buf(),
            file: file.to_path_buf(),
            as_root: false,
        }
    }

    /// A session or recording directory, or a recording file, that is not this
    /// process's own fails closed: an error, and no chmod is attempted. Root may
    /// tighten them anyway, so as root they are masked and the recording is opened.
    #[test]
    fn a_child_owned_by_someone_else_is_an_error() {
        let other = not_owned_dir_and_file();
        let (dir, file) = (other.dir.as_path(), other.file.as_path());
        let (dir_before, file_before) = (mode(dir), mode(file));

        if other.as_root {
            let (root, name) = (dir.parent().unwrap(), dir.file_name().unwrap());
            let relative = Path::new(name).join("recording");
            create_recording_directories(root, &relative).unwrap();
            assert_eq!(mode(dir), dir_before & KEEP_FOR_DIRECTORY);
            assert_ne!(mode(dir), dir_before);
            let mut open = open_recording_file(root, &relative.join("data")).unwrap();
            std::io::Write::write_all(&mut open, b"used").unwrap();
            assert_eq!(std::fs::read(dir.join("recording/data")).unwrap(), b"used");

            assert_eq!(file.parent(), Some(root));
            drop(open_recording_file(root, Path::new(file.file_name().unwrap())).unwrap());
            assert_eq!(mode(file), file_before & KEEP_FOR_RECORDING_FILE);
            assert_ne!(mode(file), file_before);
            return;
        }

        let names = |extra: &str| Path::new(dir.file_name().unwrap()).join(extra);
        let errors = [
            walk_to(dir).map(drop).unwrap_err(),
            create_recording_directories(dir.parent().unwrap(), &names("recording")).unwrap_err(),
            open_recording_file(dir.parent().unwrap(), &names("recording")).unwrap_err(),
        ];
        for err in errors {
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
            assert!(err.to_string().contains("owned by uid"), "{err}");
        }
        assert!(!dir.join("recording").exists());

        let open = std::fs::File::open(file).unwrap();
        let err = secure_open_file_by_masking(&open, KEEP_FOR_RECORDING_FILE, file).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");

        assert_eq!(mode(dir), dir_before);
        assert_eq!(mode(file), file_before);
    }

    /// A root this process can write and search but not read still gets its
    /// recording directories and files: the root is only walked from, never read.
    #[test]
    fn a_root_that_cannot_be_read_still_takes_recordings() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        set(&root, 0o300);
        let created = create_recording_directories(&root, Path::new("session/recording"));
        let opened = open_recording_file(&root, Path::new("session/recording/data"));
        let made = root.join("session/recording/data").is_file();
        set(&root, 0o700);
        created.unwrap();
        opened.unwrap();
        assert!(made);
    }

    /// A symlink in place of a recording file fails the open; its target is untouched.
    #[test]
    fn a_symlinked_recording_file_is_refused() {
        let (tmp, dir, file) = dir_and_file(0o700, 0o666);
        std::os::unix::fs::symlink(&file, dir.join("link")).unwrap();

        let err = open_recording_file(tmp.path(), Path::new("d/link")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::libc::ELOOP), "{err}");
        assert_eq!(mode(&file), 0o666);
        assert_eq!(std::fs::read(&file).unwrap(), b"x");
    }

    /// A symlink in place of a directory below the root is refused, and nothing is
    /// created or chmodded behind it, whether it is the first or a later directory.
    #[test]
    fn a_symlinked_directory_below_the_root_is_refused() {
        for (relative, link) in [("link/recording", "link"), ("real/link", "real/link")] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("root");
            let elsewhere = tmp.path().join("elsewhere");
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::fs::create_dir(&elsewhere).unwrap();
            set(&elsewhere, 0o777);
            std::os::unix::fs::symlink(&elsewhere, root.join(link)).unwrap();

            create_recording_directories(&root, Path::new(relative)).unwrap_err();
            open_recording_file(&root, &Path::new(relative).join("f")).unwrap_err();
            assert_eq!(mode(&elsewhere), 0o777, "{relative}");
            assert_eq!(
                std::fs::read_dir(&elsewhere).unwrap().count(),
                0,
                "{relative}"
            );
        }
    }

    /// `..` and absolute paths are refused, so a walk never leaves the root.
    #[test]
    fn a_walk_never_leaves_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        for relative in ["../x", "/x", "a/../../x", "./x"] {
            let err = create_recording_directories(tmp.path(), Path::new(relative)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{relative}");
        }
    }

    /// New directories and files are created at most 0o750 / 0o640 under whatever
    /// umask; existing directories and files are tightened, never widened.
    #[test]
    fn recordings_are_created_at_most_the_ceiling() {
        let umask = process_umask().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let leaf = root.join("session").join("recording");
        create_recording_directories(&root, Path::new("session/recording")).unwrap();
        for dir in [&root, &root.join("session"), &leaf] {
            assert_eq!(mode(dir), 0o750 & !umask, "{}", dir.display());
        }

        let relative = Path::new("session/recording/data.ndjson");
        drop(open_recording_file(&root, relative).unwrap());
        assert_eq!(mode(&leaf.join("data.ndjson")), 0o640 & !umask);

        // An existing file is opened as it is, for appending, and only loses bits.
        set(&leaf.join("data.ndjson"), 0o604);
        set(&leaf, 0o777);
        let mut open = open_recording_file(&root, relative).unwrap();
        std::io::Write::write_all(&mut open, b"more").unwrap();
        assert_eq!(mode(&leaf.join("data.ndjson")), 0o600);
        assert_eq!(mode(&leaf), 0o750);
    }

    /// Set in the child process [`in_a_child_with_umask_zero`] starts.
    const UMASK_ZERO_CHILD: &str = "WARPGATE_TEST_UMASK_ZERO_CHILD";

    /// Runs `body` in a copy of this test binary running only `test`, with the umask
    /// set to 0 there (a umask is per process, and the other tests share this one).
    /// Returns whether this is the child, which then has run `body`.
    fn in_a_child_with_umask_zero(test: &str, body: impl FnOnce()) -> bool {
        if std::env::var_os(UMASK_ZERO_CHILD).is_some() {
            nix::sys::stat::umask(nix::sys::stat::Mode::empty());
            body();
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--test-threads=1"])
            .env(UMASK_ZERO_CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the umask 0 child failed: {}\n{stdout}",
            output.status
        );
        // A wrong test name would run nothing and still succeed.
        assert!(
            stdout.contains("test result: ok. 1 passed;"),
            "the umask 0 child did not run exactly one test:\n{stdout}"
        );
        false
    }

    /// Under umask 0 and with no default ACL, a new directory or file gets exactly the
    /// mode it is created with, so this tells creating at 0o750 / 0o640 apart from
    /// creating wider and tightening afterwards. Checked before any tightening.
    #[test]
    fn under_umask_zero_new_directories_and_files_are_born_at_the_ceiling() {
        in_a_child_with_umask_zero(
            "helpers::fs::tests::under_umask_zero_new_directories_and_files_are_born_at_the_ceiling",
            || {
                let tmp = tempfile::tempdir().unwrap();
                let dir = std::fs::File::open(tmp.path()).unwrap();
                make_directory_at(dir.as_fd(), OsStr::new("d")).unwrap();
                assert_eq!(mode(&tmp.path().join("d")), 0o750);
                drop(open_file_at(dir.as_fd(), OsStr::new("f")).unwrap());
                assert_eq!(mode(&tmp.path().join("f")), 0o640);
            },
        );
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

        let other = not_owned_dir_and_file();
        let logged = warnings_logged(|| {
            for _ in 0..3 {
                secure_recordings_root_warning_once(&other.dir, KEEP_FOR_DIRECTORY, &warnings);
            }
        });
        assert_eq!(logged, 1);
    }
}
