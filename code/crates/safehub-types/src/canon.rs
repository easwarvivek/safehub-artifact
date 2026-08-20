//! Canonical TLS-presentation encoding for signed/hashed structures.
//!
//! Appendix C specifies TLS presentation syntax. Hashing and on-disk tip
//! persistence must use the same byte string so independent verifiers agree.

use crate::ids::{BlobId, HeadHash, RepoId};
use crate::refs::{KeyLogEntry, RefHead};

/// Encode a length-prefixed opaque vector (`opaque x<V>`): `u32 BE len || bytes`.
fn put_opaque(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("opaque length fits u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Canonical bytes for a [`RefHead`] (signatures included; matches Appendix C).
///
/// Field order matches the paper struct. Variable-length fields use
/// `uint32` big-endian length prefixes.
pub fn encode_ref_head(head: &RefHead) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&head.repo_id.0);
    out.extend_from_slice(&head.seq.to_be_bytes());
    put_opaque(&mut out, &head.enc_refs);
    out.extend_from_slice(&head.bundle_root.0);
    put_opaque(&mut out, &head.dek_wrap);
    out.extend_from_slice(&head.prev_head_hash.0);
    out.extend_from_slice(&head.mls_epoch.to_be_bytes());
    put_opaque(&mut out, &head.epoch_tag);
    out.push(u8::from(head.non_ff));
    put_opaque(&mut out, &head.pusher_sig);
    match &head.admin_cosig {
        Some(sig) => {
            out.push(1);
            put_opaque(&mut out, sig);
        }
        None => out.push(0),
    }
    out
}

/// Decode canonical [`RefHead`] bytes.
pub fn decode_ref_head(mut bytes: &[u8]) -> Result<RefHead, String> {
    fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
        if buf.len() < n {
            return Err("truncated RefHead".into());
        }
        let (a, b) = buf.split_at(n);
        *buf = b;
        Ok(a)
    }
    fn take_opaque(buf: &mut &[u8]) -> Result<Vec<u8>, String> {
        let len_bytes = take(buf, 4)?;
        let len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
        Ok(take(buf, len)?.to_vec())
    }

    let mut repo = [0u8; 32];
    repo.copy_from_slice(take(&mut bytes, 32)?);
    let mut seq_b = [0u8; 8];
    seq_b.copy_from_slice(take(&mut bytes, 8)?);
    let enc_refs = take_opaque(&mut bytes)?;
    let mut bundle = [0u8; 64];
    bundle.copy_from_slice(take(&mut bytes, 64)?);
    let dek_wrap = take_opaque(&mut bytes)?;
    let mut prev = [0u8; 64];
    prev.copy_from_slice(take(&mut bytes, 64)?);
    let mut ep_b = [0u8; 8];
    ep_b.copy_from_slice(take(&mut bytes, 8)?);
    let epoch_tag = take_opaque(&mut bytes)?;
    let non_ff = take(&mut bytes, 1)?[0] != 0;
    let pusher_sig = take_opaque(&mut bytes)?;
    let has_admin = take(&mut bytes, 1)?[0];
    let admin_cosig = if has_admin != 0 {
        Some(take_opaque(&mut bytes)?)
    } else {
        None
    };
    if !bytes.is_empty() {
        return Err("trailing bytes in RefHead".into());
    }
    Ok(RefHead {
        repo_id: RepoId(repo),
        seq: u64::from_be_bytes(seq_b),
        enc_refs,
        bundle_root: BlobId(bundle),
        dek_wrap,
        prev_head_hash: HeadHash(prev),
        mls_epoch: u64::from_be_bytes(ep_b),
        epoch_tag,
        non_ff,
        pusher_sig,
        admin_cosig,
    })
}

/// Canonical bytes for a [`KeyLogEntry`].
pub fn encode_key_log_entry(entry: &KeyLogEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&entry.drive_epoch.to_be_bytes());
    put_opaque(&mut out, &entry.wrapped_dkr);
    out.extend_from_slice(&entry.prev_hash.0);
    put_opaque(&mut out, &entry.admin_sig);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{BlobId, HeadHash, RepoId};

    fn sample_head() -> RefHead {
        RefHead {
            repo_id: RepoId([1u8; 32]),
            seq: 3,
            enc_refs: b"enc".to_vec(),
            bundle_root: BlobId([2u8; 64]),
            dek_wrap: b"dek".to_vec(),
            prev_head_hash: HeadHash([3u8; 64]),
            mls_epoch: 7,
            epoch_tag: vec![4u8; 32],
            non_ff: true,
            pusher_sig: vec![5u8; 16],
            admin_cosig: Some(vec![6u8; 8]),
        }
    }

    #[test]
    fn ref_head_roundtrip_canonical() {
        let h = sample_head();
        let bytes = encode_ref_head(&h);
        let back = decode_ref_head(&bytes).unwrap();
        assert_eq!(encode_ref_head(&back), bytes);
        assert_eq!(h.hash(), back.hash());
    }

    #[test]
    fn hash_of_received_equals_hash_of_reserialized() {
        let h = sample_head();
        let stored = encode_ref_head(&h);
        let received = decode_ref_head(&stored).unwrap();
        assert_eq!(HeadHash::of(&stored), received.hash());
        assert_eq!(HeadHash::of(&stored), HeadHash::of(&encode_ref_head(&received)));
    }
}
