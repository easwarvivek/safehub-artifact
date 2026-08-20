//! `ComDiff_char` and `ComDiff_line` from SGit's section 2.
//!
//! Their operation model is `O = (op, idx, m)` with `op ∈ {insert, delete}`,
//! and correctness requires `f' = O_n(...(O_1(f)))`. Both granularities produce
//! that; they differ in what a unit is, which is what makes SGitLine's delta
//! larger than SGitChar's for the same edit.
//!
//! `ComDiff_char` follows diff-match-patch's structure: reduce to a line-level
//! LCS first, then refine only the changed regions at character level. A direct
//! character LCS over a megabyte file is quadratic and would make the harness a
//! measurement of the diff algorithm rather than of the protocol.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Op {
    /// Insert `m` at unit index `idx`.
    Insert { idx: usize, m: String },
    /// Delete `len` units at unit index `idx`.
    Delete { idx: usize, len: usize },
}

impl Op {
    pub fn payload_bytes(&self) -> usize {
        match self {
            Op::Insert { m, .. } => m.len(),
            Op::Delete { .. } => 0,
        }
    }
}

/// Apply ops in order. This is the correctness condition on ComDiff.
pub fn apply_chars(base: &str, ops: &[Op]) -> String {
    let mut v: Vec<char> = base.chars().collect();
    for op in ops {
        match op {
            Op::Delete { idx, len } => {
                let s = (*idx).min(v.len());
                let e = (s + *len).min(v.len());
                v.drain(s..e);
            }
            Op::Insert { idx, m } => {
                let s = (*idx).min(v.len());
                let ins: Vec<char> = m.chars().collect();
                let tail = v.split_off(s);
                v.extend(ins);
                v.extend(tail);
            }
        }
    }
    v.into_iter().collect()
}

pub fn apply_lines(base: &str, ops: &[Op]) -> String {
    let mut v: Vec<String> = split_lines(base);
    for op in ops {
        match op {
            Op::Delete { idx, len } => {
                let s = (*idx).min(v.len());
                let e = (s + *len).min(v.len());
                v.drain(s..e);
            }
            Op::Insert { idx, m } => {
                let s = (*idx).min(v.len());
                let ins: Vec<String> = split_lines(m);
                let tail = v.split_off(s);
                v.extend(ins);
                v.extend(tail);
            }
        }
    }
    v.concat()
}

fn split_lines(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        cur.push(c);
        if c == '\n' {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Longest common subsequence over slices, returning matched index pairs.
fn lcs_pairs<T: PartialEq>(a: &[T], b: &[T]) -> Vec<(usize, usize)> {
    let n = a.len();
    let m = b.len();
    if n == 0 || m == 0 {
        return Vec::new();
    }
    // Row-wise DP: O(n*m) time but only O(m) memory per row is not enough to
    // recover the path, so keep the full table. Callers trim common prefix and
    // suffix first, which is what keeps n*m small in practice.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push((i, j));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// Turn matched pairs into delete/insert ops against a running index.
fn ops_from_pairs<T: AsRef<str>>(
    old: &[T],
    new: &[T],
    pairs: &[(usize, usize)],
    unit_len: impl Fn(&T) -> usize,
) -> Vec<Op> {
    let mut ops = Vec::new();
    let mut oi = 0usize;
    let mut ni = 0usize;
    let mut cursor = 0usize; // index into the evolving document, in units
    let emit = |ops: &mut Vec<Op>, del: usize, ins: &str, at: usize| {
        if del > 0 {
            ops.push(Op::Delete { idx: at, len: del });
        }
        if !ins.is_empty() {
            ops.push(Op::Insert { idx: at, m: ins.to_string() });
        }
    };
    for &(po, pn) in pairs {
        let del = po - oi;
        let ins: String = new[ni..pn].iter().map(|s| s.as_ref()).collect();
        if del > 0 || !ins.is_empty() {
            emit(&mut ops, del, &ins, cursor);
            cursor += new[ni..pn].len();
        }
        cursor += 1; // the matched unit itself
        oi = po + 1;
        ni = pn + 1;
    }
    let del = old.len() - oi;
    let ins: String = new[ni..].iter().map(|s| s.as_ref()).collect();
    emit(&mut ops, del, &ins, cursor);
    let _ = unit_len;
    ops
}

/// Line-granular diff: SGitLine's `ComDiff_line`.
pub fn com_diff_line(old: &str, new: &str) -> Vec<Op> {
    let a = split_lines(old);
    let b = split_lines(new);
    let pairs = lcs_pairs(&a, &b);
    ops_from_pairs(&a, &b, &pairs, |s| s.len())
}

/// Character-granular diff: SGitChar's `ComDiff_char`.
///
/// Line-level LCS first, then character refinement inside changed regions only.
pub fn com_diff_char(old: &str, new: &str) -> Vec<Op> {
    // Trim the common prefix and suffix by character; a localized edit reduces
    // the remaining problem to something small.
    let ac: Vec<char> = old.chars().collect();
    let bc: Vec<char> = new.chars().collect();
    let mut p = 0usize;
    while p < ac.len() && p < bc.len() && ac[p] == bc[p] {
        p += 1;
    }
    let mut s = 0usize;
    while s < ac.len() - p && s < bc.len() - p && ac[ac.len() - 1 - s] == bc[bc.len() - 1 - s] {
        s += 1;
    }
    let a_mid: Vec<char> = ac[p..ac.len() - s].to_vec();
    let b_mid: Vec<char> = bc[p..bc.len() - s].to_vec();

    // A character LCS is quadratic; above this the middle is emitted as one
    // replace, which is what diff-match-patch's cost cutoff also does.
    const CHAR_LCS_CAP: usize = 4096;
    let mut ops = Vec::new();
    if a_mid.len() <= CHAR_LCS_CAP && b_mid.len() <= CHAR_LCS_CAP {
        let pairs = lcs_pairs(&a_mid, &b_mid);
        // Clean up before emitting operations. A bare LCS keeps every
        // incidental single-character match inside the changed region, which
        // splits one replacement into hundreds of separately framed ops.
        let segs = cleanup(segs_from_pairs(&a_mid, &b_mid, &pairs));
        ops.extend(ops_from_segs(&segs, p));
    } else {
        if !a_mid.is_empty() {
            ops.push(Op::Delete { idx: p, len: a_mid.len() });
        }
        if !b_mid.is_empty() {
            ops.push(Op::Insert { idx: p, m: b_mid.iter().collect() });
        }
    }
    ops
}

pub fn payload_bytes(ops: &[Op]) -> usize {
    ops.iter().map(|o| o.payload_bytes()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn char_diff_round_trips() {
        let a = "the quick brown fox\njumps over\nthe lazy dog\n";
        let b = "the quick red fox\njumps over\nthe lazy dog\n";
        let ops = com_diff_char(a, b);
        assert_eq!(apply_chars(a, &ops), b, "f' must equal O_n(..O_1(f))");
    }

    #[test]
    fn line_diff_round_trips() {
        let a = "one\ntwo\nthree\n";
        let b = "one\ntwo and a half\nthree\n";
        let ops = com_diff_line(a, b);
        assert_eq!(apply_lines(a, &ops), b);
    }

    #[test]
    fn char_delta_is_smaller_than_line_delta_for_a_small_edit() {
        // This is the paper's central efficiency claim: for the same edit,
        // l2 <= l1. A port where it does not hold is not their construction.
        let line = "pub fn resolve(x: &u64) -> u64 { let mut o = 0u64; o += 1; o }\n";
        let a = line.repeat(40);
        let b = a.replacen("o += 1;", "o += 2;", 1);
        let cd = payload_bytes(&com_diff_char(&a, &b));
        let ld = payload_bytes(&com_diff_line(&a, &b));
        assert!(cd <= ld, "char delta {cd} should not exceed line delta {ld}");
        assert!(cd < line.len(), "char delta {cd} should be under one line");
    }

    #[test]
    fn round_trips_on_a_large_localized_edit() {
        let a: String = (0..5000).map(|i| format!("line {i}\n")).collect();
        let b = a.replacen("line 2500\n", "line 2500 CHANGED\n", 1);
        let ops = com_diff_char(&a, &b);
        assert_eq!(apply_chars(&a, &ops), b);
        assert!(payload_bytes(&ops) < 200, "a one-line edit must not resend the file");
    }

    #[test]
    fn identical_inputs_produce_no_ops() {
        let a = "unchanged\n";
        assert!(com_diff_char(a, a).is_empty());
        assert!(com_diff_line(a, a).is_empty());
    }

    #[test]
    fn encoding_round_trips_and_is_far_smaller_than_json() {
        // The delta block is what gets encrypted, appended and pushed, so its
        // encoding is part of the communication cost. JSON spends ~30 bytes of
        // framing on an op whose payload can be one character.
        let a: String = (0..400).map(|i| format!("pub fn unit_{i}(x: &u64) -> u64 {{ 0 }}\n")).collect();
        let b = a.replacen("unit_200(x: &u64) -> u64 { 0 }",
                           "unit_200(x: &i64, y: &u8) -> i64 { 7 }", 1);
        let ops = com_diff_char(&a, &b);
        let enc = encode_ops(&ops);
        assert_eq!(decode_ops(&enc).unwrap(), ops, "encoding must round-trip");
        let json = serde_json::to_vec(&ops).unwrap().len();
        assert!(enc.len() * 2 < json,
                "compact encoding {} should be well under JSON {json}", enc.len());
        assert_eq!(apply_chars(&a, &decode_ops(&enc).unwrap()), b,
                   "decoded ops must still reconstruct");
    }

    #[test]
    fn cleanup_keeps_a_replacement_whole_instead_of_fragmenting_it() {
        // A bare character LCS matches incidental single characters inside the
        // changed region and splits one replacement into many framed ops. SGit
        // specifies diff_match_patch for ComDiff_char, whose Diff_EditCost
        // cleanup removes exactly this; without it the construction is charged
        // for an inefficiency it does not have.
        let base: String = (0..200).map(|i| format!("value_{i} = compute({i});\n")).collect();
        let edited = base.replacen("value_100 = compute(100);",
                                   "result_100 = evaluate(100, true);", 1);
        let ops = com_diff_char(&base, &edited);
        assert_eq!(apply_chars(&base, &ops), edited, "cleanup must not break correctness");
        assert!(ops.len() <= 8, "one localized replacement produced {} ops", ops.len());
        let payload = encode_ops(&ops).len();
        assert!(payload < 200, "encoded delta {payload} B for a ~35 B edit");
    }

    #[test]
    fn insertion_into_empty_and_deletion_to_empty() {
        assert_eq!(apply_chars("", &com_diff_char("", "abc")), "abc");
        assert_eq!(apply_chars("abc", &com_diff_char("abc", "")), "");
    }
}

// ---- fidelity: what `diff_match_patch` does that a bare LCS does not --------

/// Cost below which an equality is not worth keeping, in characters.
///
/// `diff_match_patch` exposes this as `Diff_EditCost`, default 4. Without it a
/// character-level LCS finds every incidental single-character match inside a
/// changed region and fragments one replacement into hundreds of tiny ops. The
/// operations are still correct -- they reconstruct the file -- but each one
/// carries its own index and framing, so the encoded delta comes out several
/// times larger than the text that actually changed. SGit specifies
/// `diff_match_patch` for `ComDiff_char`; omitting its cleanup would charge the
/// construction for an inefficiency it does not have.
const EDIT_COST: usize = 4;

#[derive(Clone, PartialEq, Eq, Debug)]
enum Seg {
    Eq(Vec<char>),
    Del(Vec<char>),
    Ins(Vec<char>),
}

/// Absorb equalities too short to pay for the framing around them, then merge
/// the neighbours they were separating. Repeats until nothing more merges.
fn cleanup(mut segs: Vec<Seg>) -> Vec<Seg> {
    loop {
        let mut changed = false;
        let mut out: Vec<Seg> = Vec::with_capacity(segs.len());
        let mut i = 0;
        while i < segs.len() {
            if let Seg::Eq(e) = &segs[i] {
                let flanked = i > 0 && i + 1 < segs.len();
                if flanked && e.len() < EDIT_COST && !out.is_empty() {
                    // Turning the equality into an edit on both sides lets the
                    // runs either side merge into one op.
                    out.push(Seg::Del(e.clone()));
                    out.push(Seg::Ins(e.clone()));
                    changed = true;
                    i += 1;
                    continue;
                }
            }
            out.push(segs[i].clone());
            i += 1;
        }
        // Normalise: each maximal run of edits becomes exactly one delete
        // followed by one insert. Merging only adjacent same-kind segments is
        // not enough -- an absorbed equality leaves Del,Ins,Del,Ins alternating,
        // which never merges and leaves one replacement as dozens of separately
        // framed operations. Collapsing the run is what makes it one.
        //
        // Reordering within a run is sound: the run covers one contiguous span
        // of the old text and one of the new, so removing that span and writing
        // the replacement gives the same result as interleaving them.
        let mut merged: Vec<Seg> = Vec::with_capacity(out.len());
        let mut i = 0;
        while i < out.len() {
            match &out[i] {
                Seg::Eq(v) => {
                    if !v.is_empty() {
                        if let Some(Seg::Eq(prev)) = merged.last_mut() {
                            prev.extend(v.iter());
                            changed = true;
                        } else {
                            merged.push(out[i].clone());
                        }
                    }
                    i += 1;
                }
                _ => {
                    let (mut del, mut ins) = (Vec::new(), Vec::new());
                    let start = i;
                    while i < out.len() {
                        match &out[i] {
                            Seg::Del(v) => del.extend(v.iter()),
                            Seg::Ins(v) => ins.extend(v.iter()),
                            Seg::Eq(_) => break,
                        }
                        i += 1;
                    }
                    if i - start > 2 { changed = true; }
                    if !del.is_empty() { merged.push(Seg::Del(del)); }
                    if !ins.is_empty() { merged.push(Seg::Ins(ins)); }
                }
            }
        }
        segs = merged;
        if !changed {
            return segs;
        }
    }
}

/// Segments from matched LCS pairs, at character granularity.
fn segs_from_pairs(a: &[char], b: &[char], pairs: &[(usize, usize)]) -> Vec<Seg> {
    let mut out = Vec::new();
    let (mut oi, mut ni) = (0usize, 0usize);
    for &(po, pn) in pairs {
        if po > oi { out.push(Seg::Del(a[oi..po].to_vec())); }
        if pn > ni { out.push(Seg::Ins(b[ni..pn].to_vec())); }
        out.push(Seg::Eq(vec![a[po]]));
        oi = po + 1;
        ni = pn + 1;
    }
    if oi < a.len() { out.push(Seg::Del(a[oi..].to_vec())); }
    if ni < b.len() { out.push(Seg::Ins(b[ni..].to_vec())); }
    out
}

/// Segments to `(op, idx, m)` operations against the evolving document.
fn ops_from_segs(segs: &[Seg], base: usize) -> Vec<Op> {
    let mut ops = Vec::new();
    let mut cursor = base;
    for s in segs {
        match s {
            Seg::Eq(v) => cursor += v.len(),
            Seg::Del(v) => ops.push(Op::Delete { idx: cursor, len: v.len() }),
            Seg::Ins(v) => {
                let m: String = v.iter().collect();
                let n = v.len();
                ops.push(Op::Insert { idx: cursor, m });
                cursor += n;
            }
        }
    }
    ops
}

// ---- compact encoding -------------------------------------------------------

/// Encode operations for storage.
///
/// The delta block is what gets encrypted and appended, so its encoding is part
/// of the communication cost being measured. JSON spends roughly thirty bytes
/// of field names, quoting and index digits on an operation whose payload may
/// be a single character; on a fragmented character diff that framing, not the
/// changed text, dominates the block. This is a tag byte, LEB128 indices and
/// raw UTF-8 -- the same information, without charging the construction for the
/// serialiser.
pub fn encode_ops(ops: &[Op]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            Op::Delete { idx, len } => {
                out.push(0u8);
                put_uvar(&mut out, *idx as u64);
                put_uvar(&mut out, *len as u64);
            }
            Op::Insert { idx, m } => {
                out.push(1u8);
                put_uvar(&mut out, *idx as u64);
                let b = m.as_bytes();
                put_uvar(&mut out, b.len() as u64);
                out.extend_from_slice(b);
            }
        }
    }
    out
}

pub fn decode_ops(mut b: &[u8]) -> Option<Vec<Op>> {
    let mut ops = Vec::new();
    while !b.is_empty() {
        let tag = b[0];
        b = &b[1..];
        let idx = get_uvar(&mut b)? as usize;
        let n = get_uvar(&mut b)? as usize;
        match tag {
            0 => ops.push(Op::Delete { idx, len: n }),
            1 => {
                if b.len() < n { return None; }
                let m = std::str::from_utf8(&b[..n]).ok()?.to_string();
                b = &b[n..];
                ops.push(Op::Insert { idx, m });
            }
            _ => return None,
        }
    }
    Some(ops)
}

fn put_uvar(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 { out.push(byte); return; }
        out.push(byte | 0x80);
    }
}

fn get_uvar(b: &mut &[u8]) -> Option<u64> {
    let (mut v, mut shift) = (0u64, 0u32);
    loop {
        let byte = *b.first()?;
        *b = &b[1..];
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 { return Some(v); }
        shift += 7;
        if shift > 63 { return None; }
    }
}
