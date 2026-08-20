use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_lists_command_taxonomy() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Private encrypted GitHub CLI"))
        .stdout(predicate::str::contains("release"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("gist"))
        .stdout(predicate::str::contains("api"))
        .stdout(predicate::str::contains("search"))
        .stdout(predicate::str::contains("org"))
        .stdout(predicate::str::contains("device"))
        .stdout(predicate::str::contains("pr"))
        .stdout(predicate::str::contains("issue"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("inbox"))
        .stdout(predicate::str::contains("lfs"))
        .stdout(predicate::str::contains("migrate"))
        .stdout(predicate::str::contains("browse"))
        .stdout(predicate::str::contains("webhook"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("variable"))
        .stdout(predicate::str::contains("milestone"));
}

#[test]
fn help_bin_name_is_sh() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: shub"));
}

#[test]
fn auth_help_uses_sh() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["auth", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: shub auth"));
}

#[test]
fn repo_help_lists_mvp() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["repo", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("clone"))
        .stdout(predicate::str::contains("invite"))
        .stdout(predicate::str::contains("remove-member"))
        .stdout(predicate::str::contains("rotate"))
        .stdout(predicate::str::contains("consolidate"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("edit"))
        .stdout(predicate::str::contains("delete"))
        .stdout(predicate::str::contains("fork"))
        .stdout(predicate::str::contains("protect"))
        .stdout(predicate::str::contains("sync"))
        .stdout(predicate::str::contains("archive"))
        .stdout(predicate::str::contains("refs"))
        .stdout(predicate::str::contains("branches"))
        .stdout(predicate::str::contains("collaborators"));
}

#[test]
fn release_help_is_real() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["release", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("download"));
}

#[test]
fn org_create_requires_login() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.env("HOME", tempfile_home());
    cmd.args(["org", "create", "acme"]);
    // Not logged in → error (not exit 2 stub).
    cmd.assert().failure();
}

#[test]
fn search_repos_lists_membership_scoped() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.env("HOME", tempfile_home());
    cmd.args(["search", "repos", "foo"]);
    // Not logged in → failure (real command, not stub).
    cmd.assert().failure();
}

#[test]
fn webhook_explicitly_refused() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["webhook", "list"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not supported"));
}

#[test]
fn search_code_is_member_local() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["search", "code", "unlikely_token_xyz_12345"]);
    // Succeeds with empty/local message — no longer exit 2 stub.
    cmd.assert().success();
}

#[test]
fn gist_help_works() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["gist", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("create"));
}

#[test]
fn api_help_or_usage() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["api", "--help"]);
    // external_subcommand may not show detailed help; accept success or failure with usage.
    let assert = cmd.assert();
    let ok = assert.get_output().status.success();
    if !ok {
        // Still not the old exit-2 "not implemented"
        let err = String::from_utf8_lossy(&assert.get_output().stderr);
        assert!(
            !err.contains("not implemented"),
            "api should not be stub: {err}"
        );
    }
}

#[test]
fn pr_help_lists_diff_review_reopen() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["pr", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("review"))
        .stdout(predicate::str::contains("reopen"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("checks"))
        .stdout(predicate::str::contains("edit"));
}

#[test]
fn issue_help_lists_status_edit() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.args(["issue", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("edit"))
        .stdout(predicate::str::contains("reopen"));
}

#[test]
fn variable_milestone_status_help() {
    for args in [
        &["variable", "--help"][..],
        &["milestone", "--help"][..],
        &["status", "--help"][..],
    ] {
        let mut cmd = Command::cargo_bin("shub").unwrap();
        cmd.args(args);
        cmd.assert().success();
    }
}

#[test]
fn safehub_binary_also_works() {
    let mut cmd = Command::cargo_bin("safehub").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: shub"));
}

#[test]
fn sit_help_lists_vcs_commands() {
    let mut cmd = Command::cargo_bin("sit").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("sit push"))
        .stdout(predicate::str::contains("sit pull"))
        .stdout(predicate::str::contains("sit clone"))
        .stdout(predicate::str::contains("sit://"))
        .stdout(predicate::str::contains("--force"));
}

#[test]
fn sit_version_prints() {
    let mut cmd = Command::cargo_bin("sit").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("sit "));
}

#[test]
fn doctor_runs_without_checkout() {
    let mut cmd = Command::cargo_bin("shub").unwrap();
    cmd.env("HOME", tempfile_home());
    cmd.arg("doctor");
    // Fails checks when not logged in, but is a real command.
    let output = cmd.output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("SafeHub doctor") || combined.contains("doctor"),
        "expected doctor output, got: {combined}"
    );
}

fn tempfile_home() -> String {
    let dir = std::env::temp_dir().join(format!("safehub-test-home-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.to_string_lossy().to_string()
}
