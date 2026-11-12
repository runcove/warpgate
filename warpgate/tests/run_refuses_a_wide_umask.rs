//! `warpgate run` with `--recordings-keep-group-read` refuses to start under a umask
//! that does not cover 0077. Runs the built binary, so it fails if the check is
//! removed from the startup path.

use std::process::Command;

/// Runs `warpgate --recordings-keep-group-read --config <missing> run` under `umask`
/// and returns its exit success and output (the log goes to stdout, other errors to
/// stderr).
fn run_under_umask(umask: &str) -> (bool, String) {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("missing.yaml");
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("umask {umask} && exec \"$0\" \"$@\""))
        .arg(env!("CARGO_BIN_EXE_warpgate"))
        .arg("--recordings-keep-group-read")
        .arg("--config")
        .arg(&config)
        .arg("run")
        .output()
        .unwrap();
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn run_refuses_to_start_under_umask_0022() {
    let (ok, output) = run_under_umask("0022");
    assert!(!ok, "{output}");
    assert!(
        output.contains("--recordings-keep-group-read needs a umask that covers 0077"),
        "{output}"
    );
    assert!(output.contains("umask 0022"), "{output}");
}

/// The control: under umask 0077 the umask check passes, and the start fails only
/// later, on the missing config.
#[test]
fn run_gets_past_the_umask_check_under_umask_0077() {
    let (ok, output) = run_under_umask("0077");
    assert!(!ok, "{output}");
    assert!(!output.contains("needs a umask"), "{output}");
    assert!(output.contains("Failed to load config"), "{output}");
}
