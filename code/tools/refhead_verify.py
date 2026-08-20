#!/usr/bin/env python3
"""Independent RefHead canonical verifier (TLS-presentation bytes).

Proves third-party implementability of verifier-enforced tip policy hashing.
Does not verify ML-DSA (optional); focuses on canonical encoding + SHA-512 chain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def get_opaque(buf: memoryview, off: int) -> tuple[bytes, int]:
    if off + 4 > len(buf):
        raise ValueError("truncated opaque length")
    (n,) = struct.unpack_from(">I", buf, off)
    off += 4
    if off + n > len(buf):
        raise ValueError("truncated opaque body")
    return bytes(buf[off : off + n]), off + n


def decode_ref_head(data: bytes) -> dict:
    buf = memoryview(data)
    off = 0
    if len(buf) < 32 + 8:
        raise ValueError("too short")
    repo_id = bytes(buf[off : off + 32])
    off += 32
    (seq,) = struct.unpack_from(">Q", buf, off)
    off += 8
    enc_refs, off = get_opaque(buf, off)
    bundle_root = bytes(buf[off : off + 64])
    off += 64
    dek_wrap, off = get_opaque(buf, off)
    prev = bytes(buf[off : off + 64])
    off += 64
    (mls_epoch,) = struct.unpack_from(">Q", buf, off)
    off += 8
    epoch_tag, off = get_opaque(buf, off)
    non_ff = buf[off] != 0
    off += 1
    pusher_sig, off = get_opaque(buf, off)
    has_admin = buf[off]
    off += 1
    admin_cosig = None
    if has_admin:
        admin_cosig, off = get_opaque(buf, off)
    if off != len(buf):
        raise ValueError(f"trailing bytes: {len(buf) - off}")
    return {
        "repo_id": repo_id.hex(),
        "seq": seq,
        "enc_refs_len": len(enc_refs),
        "bundle_root": bundle_root.hex(),
        "dek_wrap_len": len(dek_wrap),
        "prev_head_hash": prev.hex(),
        "mls_epoch": mls_epoch,
        "epoch_tag_len": len(epoch_tag),
        "non_ff": non_ff,
        "pusher_sig_len": len(pusher_sig),
        "admin_cosig_len": None if admin_cosig is None else len(admin_cosig),
        "head_hash": hashlib.sha512(data).hexdigest(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", type=Path, help="canonical RefHead tip.bin or fixture")
    ap.add_argument("--expect-hash", help="optional expected SHA-512 hex of bytes")
    ap.add_argument("--json", action="store_true", help="print decoded summary JSON")
    args = ap.parse_args()
    data = args.path.read_bytes()
    # Accept legacy pretty-JSON tips by rejecting decode (caller should use .bin).
    try:
        summary = decode_ref_head(data)
    except ValueError as e:
        print(f"decode failed: {e}", file=sys.stderr)
        return 2
    got = summary["head_hash"]
    if args.expect_hash and args.expect_hash.lower() != got.lower():
        print(f"hash mismatch: got {got} expect {args.expect_hash}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"ok seq={summary['seq']} hash={got}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
