//! `sgit` — the client-side Git add-on for SGitChar / SGitLine.
//!
//! Their construction is not a remote helper and not a filter: section 4 says
//! the device keeps **two** repositories, a plaintext one the user edits and a
//! ciphertext one that is pushed, and the ciphertext repository goes to an
//! ordinary unmodified Git server with an ordinary `git push`. That is the
//! platform-compatibility property they score in Table 1, and it is how they
//! evaluated it ("we used Git tools and the GitHub API to interact with
//! GitHub").
//!
//! Getting that shape right is not pedantry. Their headline efficiency claim is
//! that pushing `C||C*` lets "the built-in deduplication mechanism remove C and
//! only upload C*" — a claim about what **Git actually transmits after delta
//! compression**, not about the size of the ciphertext the client constructs.
//! A library that only reports its own byte accounting cannot test that claim;
//! it measures the assumption instead. So the ciphertext repository here is a
//! real Git repository, pushed with real Git.
//!
//! Layout of the ciphertext repository, chosen so an update is an append:
//!
//!   <path>.sgit     line 1: base ciphertext; each later line: one delta block
//!   .sgit/acs.json  access-control file (read set, write set, owner signature)
//!   .sgit/tag.json  author and signature over the Merkle root
//!
//! Appending a line is what lets Git's delta compression ship only the new
//! line, which is the mechanism under test.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use sgit_rs::{crypto, diff, merkle, Variant};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "git {:?} failed in {}: {}",
            args,
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Every tracked file in the plaintext tree, relative path -> contents.
fn read_plain(dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let p = e?.path();
            let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            if name == ".git" || name == ".sgit" {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(s) = std::fs::read_to_string(&p) {
                let rel = p.strip_prefix(dir)?.to_string_lossy().to_string();
                out.insert(rel, s);
            }
        }
    }
    Ok(out)
}

struct Keys {
    mk: Vec<u8>,
    signer: crypto::Signer256,
    uid: String,
}

/// Per-repository sidecar beside the ciphertext repository but outside it.
///
/// Outside, because committing the master key would push it to the host. Named
/// after the repository directory, because a fixed name in the parent is shared
/// by every ciphertext repository in that directory: two repositories side by
/// side would then diff against each other's snapshot, and a sweep that puts
/// each measurement point in its own repository under one working directory
/// would silently compute every delta against the previous point's tree.
/// Where this invocation's key material lives: `--keys` when a reader was
/// handed one, otherwise the repository's own sidecar.
fn keys_file(ct: &Path, args: &[String]) -> PathBuf {
    let f = flag(args, "--keys", "");
    if f.is_empty() { sidecar(ct, "keys") } else { PathBuf::from(f) }
}

fn sidecar(ct: &Path, kind: &str) -> PathBuf {
    let stem = ct.file_name().map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "repo".to_string());
    ct.parent().unwrap_or(Path::new(".")).join(format!(".sgit-{stem}.{kind}.json"))
}


/// Reading requires key material a member already holds. Creating one here
/// instead would let `clone` and `pull` "succeed" against a repository the
/// caller cannot read, decrypting ciphertext under a fresh key and writing out
/// garbage -- a silent wrong answer where the protocol says access denied.
fn load_keys_strict(p: &Path, uid: &str) -> Result<Keys> {
    let raw = std::fs::read(p).with_context(|| format!(
        "no key material at {} -- a reader is given the repository key out of \
         band; pass --keys <file>", p.display()))?;
    let v: serde_json::Value = serde_json::from_slice(&raw)?;
    let mk = b64().decode(v["mk"].as_str().unwrap_or_default())?;
    let sk = b64().decode(v["sk"].as_str().unwrap_or_default())?;
    Ok(Keys { mk, signer: crypto::Signer256::from_bytes(&sk)?, uid: uid.to_string() })
}

fn load_or_create_keys_at(p: &Path, uid: &str) -> Result<Keys> {
    if let Ok(raw) = std::fs::read(p) {
        let v: serde_json::Value = serde_json::from_slice(&raw)?;
        let mk = b64().decode(v["mk"].as_str().unwrap_or_default())?;
        let sk = b64().decode(v["sk"].as_str().unwrap_or_default())?;
        return Ok(Keys { mk, signer: crypto::Signer256::from_bytes(&sk)?, uid: uid.to_string() });
    }
    let mut mk = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut mk);
    let signer = crypto::Signer256::generate();
    let v = serde_json::json!({
        "mk": b64().encode(&mk),
        "sk": b64().encode(signer.to_bytes()),
        "vk": b64().encode(signer.verifying_key_bytes()),
        "uid": uid,
    });
    std::fs::write(&p, serde_json::to_vec_pretty(&v)?)?;
    Ok(Keys { mk, signer, uid: uid.to_string() })
}

fn ct_file_path(ct: &Path, rel: &str) -> PathBuf {
    ct.join(format!("{rel}.sgit"))
}

/// Read a ciphertext file: first line is the base, later lines are delta blocks.
fn read_ct_file(p: &Path) -> Result<(String, Vec<String>)> {
    let s = std::fs::read_to_string(p)?;
    let mut it = s.lines();
    let base = it.next().unwrap_or_default().to_string();
    Ok((base, it.map(|l| l.to_string()).collect()))
}

fn merkle_root_of(ct: &Path) -> Result<[u8; 32]> {
    let mut leaves = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![ct.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let p = e?.path();
            let n = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            if n == ".git" {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if n.ends_with(".sgit") {
                files.push(p);
            }
        }
    }
    files.sort();
    for f in &files {
        let rel = f.strip_prefix(ct)?.to_string_lossy().to_string();
        let body = std::fs::read(f)?;
        leaves.push(crypto::sha256(&[rel.as_bytes(), &body]));
    }
    let acs = std::fs::read(ct.join(".sgit/acs.json")).unwrap_or_default();
    leaves.push(crypto::sha256(&[&acs]));
    Ok(merkle::dag_root(&leaves))
}

fn write_tag(ct: &Path, k: &Keys, rid: &str) -> Result<()> {
    let root = merkle_root_of(ct)?;
    let h = crypto::sha256(&[rid.as_bytes(), k.uid.as_bytes(), &root]);
    let tag = serde_json::json!({
        "uid": k.uid,
        "sig": b64().encode(k.signer.sign(&h)),
        "vk": b64().encode(k.signer.verifying_key_bytes()),
    });
    std::fs::create_dir_all(ct.join(".sgit"))?;
    std::fs::write(ct.join(".sgit/tag.json"), serde_json::to_vec(&tag)?)?;
    Ok(())
}

fn verify_tag(ct: &Path, rid: &str) -> Result<()> {
    let raw = std::fs::read(ct.join(".sgit/tag.json")).context("no signed tag in ciphertext repo")?;
    let v: serde_json::Value = serde_json::from_slice(&raw)?;
    let uid = v["uid"].as_str().unwrap_or_default();
    let sig = b64().decode(v["sig"].as_str().unwrap_or_default())?;
    let vk = b64().decode(v["vk"].as_str().unwrap_or_default())?;
    let root = merkle_root_of(ct)?;
    let h = crypto::sha256(&[rid.as_bytes(), uid.as_bytes(), &root]);
    if !crypto::verify(&vk, &h, &sig) {
        return Err(anyhow!(
            "ciphertext repository does not verify against its signed Merkle root: \
             it has been modified since it was pushed"
        ));
    }
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "sgit — client-side Git add-on for SGitChar/SGitLine\n\
         \n\
         sgit init   <plain> <ct> <remote-url> [--variant char|line] [--uid U]\n\
         sgit push   <plain> <ct> [--variant char|line]\n\
         sgit clone  <remote-url> <plain> <ct> [--variant char|line]\n\
         sgit pull   <plain> <ct> [--variant char|line]\n\
         \n\
         --keys <file>  key material for this repository. Writers default to the\n\
                        repository's own sidecar; readers of a cloned repository\n\
                        must be given one, as a member would be out of band.\n\
         \n\
         The ciphertext repository is an ordinary Git repository pushed to an\n\
         ordinary Git server; the plaintext repository never leaves the device."
    );
    std::process::exit(2)
}

fn flag(args: &[String], name: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let variant = Variant::parse(&flag(&args, "--variant", "char"))?;
    let uid = flag(&args, "--uid", "alice");
    let rid = "sgit-repo";

    match args[0].as_str() {
        "init" => {
            if args.len() < 4 {
                usage();
            }
            let (plain, ct, remote) = (Path::new(&args[1]), Path::new(&args[2]), &args[3]);
            std::fs::create_dir_all(plain)?;
            std::fs::create_dir_all(ct)?;
            git(ct, &["init", "-q", "--initial-branch=main"])?;
            git(ct, &["config", "user.email", "sgit@eval.invalid"])?;
            git(ct, &["config", "user.name", "sgit"])?;
            git(ct, &["remote", "add", "origin", remote])?;
            let k = load_or_create_keys_at(&keys_file(ct, &args), &uid)?;
            std::fs::create_dir_all(ct.join(".sgit"))?;
            let acs = serde_json::json!({ "read": {}, "write": [uid] });
            std::fs::write(ct.join(".sgit/acs.json"), serde_json::to_vec(&acs)?)?;
            write_tag(ct, &k, rid)?;
            git(ct, &["add", "-A"])?;
            git(ct, &["commit", "-qm", "sgit init"])?;
            println!("initialized: plaintext {} ciphertext {}", plain.display(), ct.display());
        }
        "push" => {
            if args.len() < 3 {
                usage();
            }
            let (plain, ct) = (Path::new(&args[1]), Path::new(&args[2]));
            let k = load_or_create_keys_at(&keys_file(ct, &args), &uid)?;
            let key = crypto::kdf(&k.mk, rid);
            let new = read_plain(plain)?;
            // The last pushed plaintext, kept beside the keys: the diff is
            // against what the ciphertext repository currently encodes.
            let snap_path = sidecar(ct, "snapshot");
            let old: BTreeMap<String, String> = std::fs::read(&snap_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();

            let mut changed = 0usize;
            for (name, body) in &new {
                let p = ct_file_path(ct, name);
                match old.get(name) {
                    Some(prev) if prev == body => continue,
                    Some(prev) => {
                        std::fs::create_dir_all(p.parent().unwrap())?;
                        match variant {
                            Variant::Char => {
                                // Diff-then-Enc-then-Sign: append the encrypted
                                // delta so Git ships only the appended line.
                                let ops = diff::com_diff_char(prev, body);
                                let blob = diff::encode_ops(&ops);
                                let line = b64().encode(crypto::enc(&key, &blob));
                                let mut f = std::fs::OpenOptions::new().append(true).open(&p)?;
                                writeln!(f, "{line}")?;
                            }
                            Variant::Line => {
                                let mut out = String::new();
                                for l in body.split_inclusive('\n') {
                                    out.push_str(&b64().encode(crypto::enc(&key, l.as_bytes())));
                                    out.push('\n');
                                }
                                std::fs::write(&p, out)?;
                            }
                        }
                        changed += 1;
                    }
                    None => {
                        std::fs::create_dir_all(p.parent().unwrap())?;
                        match variant {
                            Variant::Char => {
                                std::fs::write(&p, format!("{}\n", b64().encode(crypto::enc(&key, body.as_bytes()))))?;
                            }
                            Variant::Line => {
                                let mut out = String::new();
                                for l in body.split_inclusive('\n') {
                                    out.push_str(&b64().encode(crypto::enc(&key, l.as_bytes())));
                                    out.push('\n');
                                }
                                std::fs::write(&p, out)?;
                            }
                        }
                        changed += 1;
                    }
                }
            }
            let mut deleted = 0usize;
            for name in old.keys() {
                if !new.contains_key(name) {
                    let _ = std::fs::remove_file(ct_file_path(ct, name));
                    deleted += 1;
                }
            }

            // Nothing changed means nothing to version. Signing is RFC6979
            // deterministic (see crypto.rs), so re-signing an unchanged tree
            // reproduces `tag.json` byte for byte and Git finds nothing to
            // commit -- which the previous `let _ = git(commit)` swallowed,
            // hiding a genuinely failed commit just as effectively. Returning
            // early instead makes the commit status checkable, and skips a
            // Merkle root recomputation over the whole repository. The harness
            // measures its floor as exactly this call, so the work it does not
            // do here is work that does not get subtracted from every other
            // measurement.
            if changed == 0 && deleted == 0 {
                git(ct, &["push", "-q", "origin", "HEAD"])?;
                println!("Everything up-to-date");
                return Ok(());
            }

            write_tag(ct, &k, rid)?;
            std::fs::write(&snap_path, serde_json::to_vec(&new)?)?;
            git(ct, &["add", "-A"])?;
            git(ct, &["commit", "-qm", "sgit update"])?;
            git(ct, &["push", "-q", "origin", "HEAD"])?;
            println!("pushed {changed} changed, {deleted} deleted file(s)");
        }
        "clone" => {
            if args.len() < 4 {
                usage();
            }
            let (remote, plain, ct) = (&args[1], Path::new(&args[2]), Path::new(&args[3]));
            git(Path::new("."), &["clone", "-q", remote, &ct.to_string_lossy()])?;
            verify_tag(ct, rid)?;
            let k = load_keys_strict(&keys_file(ct, &args), &uid)?;
            decrypt_into(ct, plain, &crypto::kdf(&k.mk, rid), variant)?;
            println!("cloned and decrypted into {}", plain.display());
        }
        "pull" => {
            if args.len() < 3 {
                usage();
            }
            let (plain, ct) = (Path::new(&args[1]), Path::new(&args[2]));
            git(ct, &["pull", "-q", "--ff-only", "origin", "main"])?;
            verify_tag(ct, rid)?;
            let k = load_keys_strict(&keys_file(ct, &args), &uid)?;
            decrypt_into(ct, plain, &crypto::kdf(&k.mk, rid), variant)?;
            println!("pulled and decrypted into {}", plain.display());
        }
        _ => usage(),
    }
    Ok(())
}

/// Reconstruct the plaintext tree: decrypt the base, then replay each appended
/// delta in order.
fn decrypt_into(ct: &Path, plain: &Path, key: &[u8; 32], v: Variant) -> Result<()> {
    std::fs::create_dir_all(plain)?;
    let mut stack = vec![ct.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let p = e?.path();
            let n = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            if n == ".git" || n == ".sgit" {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if !n.ends_with(".sgit") {
                continue;
            }
            let rel = p.strip_prefix(ct)?.to_string_lossy().to_string();
            let rel = rel.trim_end_matches(".sgit").to_string();
            let (base, deltas) = read_ct_file(&p)?;
            let body = match v {
                Variant::Char => {
                    let mut text = String::from_utf8(crypto::dec(key, &b64().decode(base.as_bytes())?)?)?;
                    for blk in &deltas {
                        let raw = crypto::dec(key, &b64().decode(blk.as_bytes())?)?;
                        let ops: Vec<diff::Op> = diff::decode_ops(&raw)
                            .ok_or_else(|| anyhow!("malformed delta block in ciphertext"))?;
                        text = diff::apply_chars(&text, &ops);
                    }
                    text
                }
                Variant::Line => {
                    let mut text = String::new();
                    for l in std::iter::once(base).chain(deltas) {
                        if l.is_empty() {
                            continue;
                        }
                        text.push_str(&String::from_utf8(crypto::dec(key, &b64().decode(l.as_bytes())?)?)?);
                    }
                    text
                }
            };
            let out = plain.join(&rel);
            std::fs::create_dir_all(out.parent().unwrap())?;
            std::fs::write(out, body)?;
        }
    }
    Ok(())
}
