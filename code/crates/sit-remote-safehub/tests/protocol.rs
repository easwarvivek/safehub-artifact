//! Protocol-level tests for the sit remote helper (no server required).

use sit_remote_safehub::run_helper;
use std::io::Cursor;

#[tokio::test]
async fn capabilities_then_eof() {
    let input = b"capabilities\n";
    let mut out = Vec::new();
    run_helper("alice/widgets", Cursor::new(&input[..]), &mut out)
        .await
        .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("fetch\n"));
    assert!(s.contains("push\n"));
    assert!(s.contains("option\n"));
    // Trailing blank line ends the capabilities advertisement.
    assert!(s.ends_with("\n\n") || s.contains("option\n\n"));
}

#[tokio::test]
async fn option_ok() {
    let input = b"capabilities\noption verbosity 1\n";
    let mut out = Vec::new();
    run_helper("alice/widgets", Cursor::new(&input[..]), &mut out)
        .await
        .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("ok\n"));
}

#[tokio::test]
async fn empty_list_without_credentials_is_graceful() {
    let input = b"list\n";
    let mut out = Vec::new();
    run_helper("alice/widgets", Cursor::new(&input[..]), &mut out)
        .await
        .expect("list must not fail hard");
    // Empty remote: only the terminating blank line.
    assert_eq!(String::from_utf8(out).unwrap(), "\n");
}

#[tokio::test]
async fn push_batch_reports_error_without_repo() {
    let input = b"push refs/heads/main:refs/heads/main\n\n";
    let mut out = Vec::new();
    run_helper("alice/widgets", Cursor::new(&input[..]), &mut out)
        .await
        .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.starts_with("error refs/heads/main "), "{s}");
    assert!(s.ends_with("\n\n") || s.contains("\n\n"));
}
