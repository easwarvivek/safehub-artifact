//! Independent reimplementation of **SGitChar** and **SGitLine** from
//! "End-to-End Encrypted Git Services" (Li, Song, Tang and Yung, ACM CCS 2025;
//! ePrint 2025/1208), for comparative evaluation.
//!
//! The authors state in section 5 that they "will open-source it soon"; across
//! three ePrint revisions, the ACM camera-ready and the first author's
//! publication page, no artifact is available. This follows their Figure 6
//! construction and section 5 parameters (AES-CTR, ECDSA, SHA-256,
//! HKDF-SHA-256, a Merkle DAG over ciphertext files, Base64 ciphertext
//! encoding). It is **our** reimplementation, and the paper says so.
//!
//! What is faithful, and therefore comparable:
//!
//! * **SGitChar** encrypts the first version of a file whole, then for each
//!   update computes a character-level delta, encrypts it, and *appends* the
//!   result to the ciphertext file. That append is the whole trick: Git's
//!   deduplication then transmits only the appended part.
//! * **SGitLine** encrypts line by line and replaces the ciphertext of changed
//!   lines in place. Each version is self-contained, at the cost of a larger
//!   delta and of leaking edit positions.
//! * Unforgeability comes from signing a Merkle-DAG root over the ciphertext
//!   files rather than signing each file, so cost is logarithmic in file count.
//! * Ciphertext is Base64-encoded, which the paper records as a ~30% expansion
//!   needed to survive a Git host's format checks. Omitting it would understate
//!   every storage and communication number.
//!
//! What is deliberately out of scope: revocation, which the paper states it does
//! not consider; and adaptive corruption, which its model excludes.

pub mod crypto;
pub mod diff;
pub mod merkle;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use diff::Op;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Character-granular delta, appended to the ciphertext file.
    Char,
    /// Line-granular ciphertext, replaced in place.
    Line,
}

impl Variant {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "char" | "sgitchar" => Ok(Variant::Char),
            "line" | "sgitline" => Ok(Variant::Line),
            other => Err(anyhow!("unknown variant {other}; expected char or line")),
        }
    }
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Access-control file `f_acs`: read set carries the repository key wrapped to
/// each member, write set names who may author a version, and the owner signs
/// both.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccessFile {
    pub read: BTreeMap<String, String>,
    pub write: Vec<String>,
    pub sig: String,
}

/// Commit tag `f_tag = (uid, sigma)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tag {
    pub uid: String,
    pub sig: String,
}

/// One ciphertext file. For SGitChar this is a base ciphertext plus an ordered
/// list of encrypted delta blocks; for SGitLine, one ciphertext per line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtFile {
    pub base: String,
    #[serde(default)]
    pub deltas: Vec<String>,
    #[serde(default)]
    pub lines: Vec<String>,
}

impl CtFile {
    /// Bytes a host would store for this file, after Base64.
    pub fn stored_bytes(&self) -> usize {
        self.base.len()
            + self.deltas.iter().map(|d| d.len()).sum::<usize>()
            + self.lines.iter().map(|l| l.len()).sum::<usize>()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtRepo {
    pub rid: String,
    pub files: BTreeMap<String, CtFile>,
    pub acs: AccessFile,
    pub tag: Tag,
}

pub struct Member {
    pub uid: String,
    pub mk: Vec<u8>,
    pub signer: crypto::Signer256,
}

impl Member {
    pub fn new(uid: &str) -> Self {
        let mut mk = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut mk);
        Self { uid: uid.to_string(), mk, signer: crypto::Signer256::generate() }
    }
    pub fn key_for(&self, rid: &str) -> [u8; 32] {
        crypto::kdf(&self.mk, rid)
    }
}

/// What one update cost, so the harness can report bytes rather than only time.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateCost {
    /// Plaintext bytes the diff identified as changed.
    pub delta_plaintext_bytes: usize,
    /// Ciphertext bytes newly written, i.e. what a push transmits.
    pub delta_ciphertext_bytes: usize,
    /// Total bytes the host stores after this update.
    pub stored_bytes: usize,
    pub files_touched: usize,
}

fn acs_message(acs: &AccessFile) -> Vec<u8> {
    // Sign(sk_s, f_acs.W || f_acs.R) per Figure 6. The access sets must be
    // inside the signed message: signing a constant would leave them
    // unauthenticated, letting a host grant itself write access without
    // invalidating anything.
    let mut m = b"sgit-acs".to_vec();
    for w in &acs.write {
        m.extend_from_slice(w.as_bytes());
        m.push(0x1f);
    }
    m.push(0x1e);
    for (uid, wrap) in &acs.read {
        m.extend_from_slice(uid.as_bytes());
        m.push(0x1f);
        m.extend_from_slice(wrap.as_bytes());
        m.push(0x1f);
    }
    m
}

fn sign_root(m: &Member, rid: &str, root: &[u8; 32]) -> String {
    let h = crypto::sha256(&[rid.as_bytes(), m.uid.as_bytes(), root]);
    b64().encode(m.signer.sign(&h))
}

fn ct_root(files: &BTreeMap<String, CtFile>, acs: &AccessFile) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for (name, f) in files {
        let mut parts: Vec<&[u8]> = vec![name.as_bytes(), f.base.as_bytes()];
        for d in &f.deltas {
            parts.push(d.as_bytes());
        }
        for l in &f.lines {
            parts.push(l.as_bytes());
        }
        leaves.push(crypto::sha256(&parts));
    }
    leaves.push(crypto::sha256(&[acs.sig.as_bytes()]));
    merkle::dag_root(&leaves)
}

/// `Pi_init`: encrypt the first version, hash the ciphertext DAG, sign the root.
pub fn init(m: &Member, rid: &str, plain: &BTreeMap<String, String>, v: Variant) -> Result<CtRepo> {
    let k = m.key_for(rid);
    let mut files = BTreeMap::new();
    for (name, body) in plain {
        let f = match v {
            Variant::Char => CtFile {
                base: b64().encode(crypto::enc(&k, body.as_bytes())),
                deltas: Vec::new(),
                lines: Vec::new(),
            },
            Variant::Line => CtFile {
                base: String::new(),
                deltas: Vec::new(),
                lines: body
                    .split_inclusive('\n')
                    .map(|l| b64().encode(crypto::enc(&k, l.as_bytes())))
                    .collect(),
            },
        };
        files.insert(name.clone(), f);
    }
    let mut acs = AccessFile::default();
    acs.write.push(m.uid.clone());
    acs.sig = b64().encode(m.signer.sign(&acs_message(&acs)));
    let root = ct_root(&files, &acs);
    Ok(CtRepo { rid: rid.to_string(), files, acs, tag: Tag { uid: m.uid.clone(), sig: sign_root(m, rid, &root) } })
}

/// `Pi_update`: diff against the last plaintext, encrypt only the difference,
/// and re-sign the root.
pub fn update(
    m: &Member,
    repo: &mut CtRepo,
    old_plain: &BTreeMap<String, String>,
    new_plain: &BTreeMap<String, String>,
    v: Variant,
) -> Result<UpdateCost> {
    let k = m.key_for(&repo.rid);
    let mut cost = UpdateCost::default();

    for (name, new_body) in new_plain {
        match old_plain.get(name) {
            None => {
                // A new file is encrypted as in init.
                let f = match v {
                    Variant::Char => CtFile {
                        base: b64().encode(crypto::enc(&k, new_body.as_bytes())),
                        deltas: Vec::new(),
                        lines: Vec::new(),
                    },
                    Variant::Line => CtFile {
                        base: String::new(),
                        deltas: Vec::new(),
                        lines: new_body
                            .split_inclusive('\n')
                            .map(|l| b64().encode(crypto::enc(&k, l.as_bytes())))
                            .collect(),
                    },
                };
                cost.delta_plaintext_bytes += new_body.len();
                cost.delta_ciphertext_bytes += f.stored_bytes();
                cost.files_touched += 1;
                repo.files.insert(name.clone(), f);
            }
            Some(old_body) if old_body != new_body => {
                let f = repo
                    .files
                    .get_mut(name)
                    .ok_or_else(|| anyhow!("ciphertext missing for tracked file {name}"))?;
                match v {
                    Variant::Char => {
                        // Encrypt the character delta and APPEND it. Git's
                        // deduplication then transmits only this block, which is
                        // the construction's whole efficiency argument.
                        let ops = diff::com_diff_char(old_body, new_body);
                        let blob = diff::encode_ops(&ops);
                        let block = b64().encode(crypto::enc(&k, &blob));
                        cost.delta_plaintext_bytes += diff::payload_bytes(&ops);
                        cost.delta_ciphertext_bytes += block.len();
                        f.deltas.push(block);
                    }
                    Variant::Line => {
                        // Replace the ciphertext of changed lines in place, so
                        // each version stands alone.
                        let ops = diff::com_diff_line(old_body, new_body);
                        cost.delta_plaintext_bytes += diff::payload_bytes(&ops);
                        let mut lines: Vec<String> = f.lines.clone();
                        for op in &ops {
                            match op {
                                Op::Delete { idx, len } => {
                                    let s = (*idx).min(lines.len());
                                    let e = (s + *len).min(lines.len());
                                    lines.drain(s..e);
                                }
                                Op::Insert { idx, m: text } => {
                                    let s = (*idx).min(lines.len());
                                    let mut enc_lines: Vec<String> = text
                                        .split_inclusive('\n')
                                        .map(|l| b64().encode(crypto::enc(&k, l.as_bytes())))
                                        .collect();
                                    cost.delta_ciphertext_bytes +=
                                        enc_lines.iter().map(|l| l.len()).sum::<usize>();
                                    let tail = lines.split_off(s);
                                    lines.append(&mut enc_lines);
                                    lines.extend(tail);
                                }
                            }
                        }
                        f.lines = lines;
                    }
                }
                cost.files_touched += 1;
            }
            Some(_) => {}
        }
    }
    for name in old_plain.keys() {
        if !new_plain.contains_key(name) {
            repo.files.remove(name);
        }
    }

    let root = ct_root(&repo.files, &repo.acs);
    repo.tag = Tag { uid: m.uid.clone(), sig: sign_root(m, &repo.rid, &root) };
    cost.stored_bytes = repo.files.values().map(|f| f.stored_bytes()).sum();
    Ok(cost)
}

/// `Pi_pull`: verify the signature over the Merkle root, then reconstruct.
pub fn pull(
    m: &Member,
    repo: &CtRepo,
    author_vk: &[u8],
    v: Variant,
) -> Result<BTreeMap<String, String>> {
    // The owner's signature over the access sets is checked first: without it a
    // host could add itself to the write set and then author versions.
    let acs_sig = b64().decode(repo.acs.sig.as_bytes()).context("acs signature is not base64")?;
    if !crypto::verify(author_vk, &acs_message(&repo.acs), &acs_sig) {
        return Err(anyhow!("access-control file is not signed by the repository owner"));
    }
    if !repo.acs.write.contains(&repo.tag.uid) {
        return Err(anyhow!("version authored by {} who has no write access", repo.tag.uid));
    }
    let root = ct_root(&repo.files, &repo.acs);
    let h = crypto::sha256(&[repo.rid.as_bytes(), repo.tag.uid.as_bytes(), &root]);
    let sig = b64().decode(repo.tag.sig.as_bytes()).context("tag signature is not base64")?;
    if !crypto::verify(author_vk, &h, &sig) {
        return Err(anyhow!("version signature does not verify: repository is forged or corrupt"));
    }

    let k = m.key_for(&repo.rid);
    let mut out = BTreeMap::new();
    for (name, f) in &repo.files {
        let body = match v {
            Variant::Char => {
                let base = crypto::dec(&k, &b64().decode(f.base.as_bytes())?)?;
                let mut text = String::from_utf8(base)?;
                for block in &f.deltas {
                    let raw = crypto::dec(&k, &b64().decode(block.as_bytes())?)?;
                    let ops: Vec<Op> = diff::decode_ops(&raw)
                        .ok_or_else(|| anyhow!("malformed delta block"))?;
                    text = diff::apply_chars(&text, &ops);
                }
                text
            }
            Variant::Line => {
                let mut text = String::new();
                for l in &f.lines {
                    let pt = crypto::dec(&k, &b64().decode(l.as_bytes())?)?;
                    text.push_str(&String::from_utf8(pt)?);
                }
                text
            }
        };
        out.insert(name.clone(), body);
    }
    Ok(out)
}

/// `Pi_shareI`: wrap the repository key to a recipient and record the grant.
pub fn share(owner: &Member, repo: &mut CtRepo, recipient_uid: &str, write: bool) -> Result<()> {
    // The paper wraps under the recipient's public-key encryption key. Modelling
    // that as an authenticated wrap keeps the size and the signing structure;
    // the arm is compared on bytes and scaling, and the paper states this is a
    // reimplementation.
    let k = owner.key_for(&repo.rid);
    let wrap = b64().encode(crypto::enc(&crypto::kdf(recipient_uid.as_bytes(), "share"), &k));
    repo.acs.read.insert(recipient_uid.to_string(), wrap);
    if write && !repo.acs.write.iter().any(|u| u == recipient_uid) {
        repo.acs.write.push(recipient_uid.to_string());
    }
    repo.acs.sig = b64().encode(owner.signer.sign(&acs_message(&repo.acs)));
    let root = ct_root(&repo.files, &repo.acs);
    repo.tag = Tag { uid: owner.uid.clone(), sig: sign_root(owner, &repo.rid, &root) };
    Ok(())
}

pub fn write_repo(dir: &Path, repo: &CtRepo) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let p = dir.join("repo.ct.json");
    std::fs::write(&p, serde_json::to_vec(repo)?)?;
    Ok(p)
}

pub fn read_repo(dir: &Path) -> Result<CtRepo> {
    let p = dir.join("repo.ct.json");
    Ok(serde_json::from_slice(&std::fs::read(&p)?)?)
}
