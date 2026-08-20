//! Merkle DAG over ciphertext files, as SGit's Figure 6 uses it.
//!
//! Their unforgeability argument signs the root of a DAG-structured hash over
//! the ciphertext files and their layout rather than signing each file, so a
//! single-file change costs hashing on the path to the root rather than work
//! proportional to the whole version. Reproducing that structure matters for
//! the computation numbers, not just for correctness.

use sha2::{Digest, Sha256};

const NODE_TAG: &[u8] = b"sgit-merkle-node";
const EMPTY_TAG: &[u8] = b"sgit-merkle-empty";

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NODE_TAG);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Root over `leaves`; an odd level duplicates its last node.
pub fn dag_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut h = Sha256::new();
        h.update(EMPTY_TAG);
        return h.finalize().into();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let r = pair.get(1).unwrap_or(&pair[0]);
            next.push(node(&pair[0], r));
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: u8) -> [u8; 32] { [b; 32] }

    #[test]
    fn root_changes_when_any_leaf_changes() {
        let a = dag_root(&[leaf(1), leaf(2), leaf(3)]);
        let b = dag_root(&[leaf(1), leaf(2), leaf(4)]);
        assert_ne!(a, b, "a changed ciphertext file must change the signed root");
    }

    #[test]
    fn root_is_order_sensitive() {
        assert_ne!(dag_root(&[leaf(1), leaf(2)]), dag_root(&[leaf(2), leaf(1)]),
                   "layout is part of what is signed");
    }

    #[test]
    fn empty_and_single_are_defined_and_distinct() {
        assert_ne!(dag_root(&[]), dag_root(&[leaf(0)]));
    }

    #[test]
    fn root_is_deterministic() {
        assert_eq!(dag_root(&[leaf(7), leaf(8), leaf(9)]),
                   dag_root(&[leaf(7), leaf(8), leaf(9)]));
    }
}
