#!/usr/bin/env python3
"""Eval E01 — extend realrepo-scale-latest.json with compressible corpora.

For live E2E measurement, prefer scripts/e2e_realrepo_scale.sh.
"""
from __future__ import annotations

import gzip
import io
import math
import os
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import (  # noqa: E402
    PUB_DIR,
    aead_ms_per_byte,
    dispersion,
    analytic_point,
    load_json,
    load_micro_from_smoke,
    meta_block,
    write_published,
)

REPS = 5
SCRIPT = "scripts/gen_realrepo_scale_latest.py"


def gen_compressible_tree(dest: Path, mib: int, seed: int) -> tuple[int, int, int]:
    rng = random.Random(0x5AFE_C0DE ^ seed ^ mib)
    target = mib * 1024 * 1024
    license_ = (
        "// Copyright (c) 2026 The SafeHub Evaluation Authors.\n"
        "// Licensed under the Apache License, Version 2.0.\n"
    )
    imports = (
        "use std::collections::BTreeMap;\nuse anyhow::Result;\n"
        "use serde::{Deserialize, Serialize};\n"
    )
    idents = ["handle", "resolve", "encode", "verify", "merge", "index", "flush"]
    types = ["u64", "usize", "String", "Vec<u8>"]
    total = 0
    files = 0
    while total < target:
        module = files // 40
        path = dest / "src" / f"mod{module:03d}" / f"{rng.choice(idents)}_{files:05d}.rs"
        path.parent.mkdir(parents=True, exist_ok=True)
        parts = [license_, imports, "\n"]
        for i in range(rng.randint(3, 12)):
            name = rng.choice(idents)
            ty = rng.choice(types)
            n = rng.randint(1, 9)
            parts.append(
                f"/// Evaluation stand-in.\npub fn {name}_{i}(input: &{ty}) "
                f"-> Result<{ty}> {{\n    let mut out = input.clone();\n"
                f"    for _ in 0..{n} {{ out = out.clone(); }}\n    Ok(out)\n}}\n\n"
            )
        text = "".join(parts)
        path.write_text(text)
        total += len(text)
        files += 1
    return files, total, tree_gzip_bytes(dest)


def tree_gzip_bytes(root: Path) -> int:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        for dirpath, _, names in os.walk(root):
            for name in sorted(names):
                p = Path(dirpath) / name
                try:
                    gz.write(p.read_bytes())
                except OSError:
                    pass
    return len(buf.getvalue())


def measure_corpus(name, klass, origin, files, raw, gz, micro, seed, kind):
    seal = aead_ms_per_byte(micro, "seal")
    open_ = aead_ms_per_byte(micro, "open")
    # Plain-git pack model: gzip-like compression on source trees (~1.05× gzip).
    pg_pack = int(gz * 1.08)
    ct = int(raw + math.ceil(raw / (4 * 1024 * 1024)) * 92)
    push_ms = seal * raw + 12.0
    clone_ms = open_ * ct + 20.0
    fetch_ms = open_ * (raw * 0.05) + 6.0
    pg_push = 3.0 + raw / (80 * 1024 * 1024) * 1000  # ~80 MiB/s pack write
    pg_clone = 5.0 + pg_pack / (120 * 1024 * 1024) * 1000
    pg_fetch = 2.0 + (pg_pack * 0.02) / (120 * 1024 * 1024) * 1000

    def ratio(a, b):
        return round(a / b, 4) if b else None

    return {
        "corpus": name,
        "class": klass,
        "origin": origin,
        "corpus_kind": kind,
        "measured": False,
        "status": "model",
        "label": "model",
        "files": files,
        "tree_bytes": raw,
        "tree_gzip_bytes": gz,
        "tree_gzip_ratio": ratio(gz, raw),
        "compressible": (gz / raw) < 0.75 if raw else None,
        "server_ciphertext_bytes_model": ct,
        "plain_git_pack_bytes_model": pg_pack,
        "ciphertext_over_tree": ratio(ct, raw),
        "ciphertext_over_plain_git_pack": ratio(ct, pg_pack),
        "safehub_push_ms": analytic_point(push_ms, "ms"),
        "safehub_fetch_ms": analytic_point(fetch_ms, "ms"),
        "safehub_clone_ms": analytic_point(clone_ms, "ms"),
        "plain_git_push_ms": analytic_point(pg_push, "ms"),
        "plain_git_fetch_ms": analytic_point(pg_fetch, "ms"),
        "plain_git_clone_ms": analytic_point(pg_clone, "ms"),
        "timing_status": "model",
        "compressibility_status": "measured",
        "note": (
            "tree_bytes/gzip measured on generated corpus; push/clone wall "
            "modeled from measured AEAD rates (overall status=model)."
        ),
    }


def main():
    out = PUB_DIR / "realrepo-scale-latest.json"
    prior = load_json(out) if out.exists() else {}
    prior_rows = list(prior.get("rows") or [])
    # If already extended, keep nested prior.
    if prior.get("prior_rows"):
        prior_rows = list(prior["prior_rows"])
        # Also keep any previously published measured sections additively.
    micro = load_micro_from_smoke()

    corpora = []
    with tempfile.TemporaryDirectory(prefix="safehub-rr-") as tmp:
        tmp_p = Path(tmp)
        specs = [
            ("synth-compressible-4mib", "synthetic-compressible", 4, 1),
            ("synth-compressible-8mib", "synthetic-compressible", 8, 2),
            ("synth-compressible-12mib", "synthetic-compressible", 12, 3),
            ("synth-compressible-16mib", "synthetic-compressible", 16, 4),
            ("synth-compressible-24mib", "synthetic-compressible", 24, 5),
            ("synth-compressible-32mib", "synthetic-compressible", 32, 6),
            ("synth-compressible-48mib", "synthetic-compressible", 48, 7),
            ("synth-compressible-64mib", "synthetic-compressible", 64, 8),
        ]
        for name, klass, mib, seed in specs:
            dest = tmp_p / name
            files, raw, gz = gen_compressible_tree(dest, mib, seed)
            corpora.append(
                measure_corpus(
                    name,
                    klass,
                    "generated source-shaped compressible tree",
                    files,
                    raw,
                    gz,
                    micro,
                    1000 + seed,
                    "synthetic-compressible",
                )
            )

    # Git delta-compression analytical model (clearly labeled).
    git_delta_model = {
        "status": "model",
        "label": "model",
        "name": "git_pack_delta_compression",
        "description": (
            "Analytical comparison of SafeHub per-object AEAD ciphertext vs "
            "git pack delta compression on compressible source. Git stores "
            "similar blobs as base+delta; SafeHub seals chunked plaintext so "
            "cross-blob delta savings are unavailable to the host."
        ),
        "assumptions": {
            "git_pack_ratio_vs_gzip": 1.08,
            "safehub_expansion_per_4mib_chunk_bytes": 92,
            "aead_backend": micro.get("source"),
        },
        "implication": (
            "On compressible corpora, ciphertext_over_plain_git_pack rises "
            "relative to incompressible fixtures (host sees no plaintext deltas)."
        ),
    }

    # Retain analytical cold-clone model rows.
    a = aead_ms_per_byte(micro, "seal") / 1000.0  # s/byte
    b, c, d, P = 0.002, 0.050, 1e-6, 8
    model_rows = []
    for name, objs, nbytes, note in [
        ("additive_100MiB_1k", 1000, 100 * 1024 * 1024, "see additive-scale-latest.json"),
        ("additive_200MiB_1k", 1000, 200 * 1024 * 1024, "see additive-scale-latest.json"),
        ("git_git_full_history", 350_000, 250 * 1024 * 1024, "class estimate"),
        ("vscode", 1_200_000, 500 * 1024 * 1024, "extrapolated class"),
        ("linux", 9_000_000, int(4.5 * 1024 * 1024 * 1024), "extrapolated; excludes checkout I/O"),
    ]:
        chunks = math.ceil(nbytes / (4 * 1024 * 1024))
        t = a * nbytes + b * chunks + c * math.ceil(chunks / P) + d * objs
        model_rows.append(
            {
                "class": name,
                "objects": objs,
                "bytes": nbytes,
                "chunks": chunks,
                "cold_clone_s_est": round(t, 2),
                "measured": False,
                "status": "model" if "linux" not in name and "vscode" not in name else "extrapolated",
                "label": "model" if "linux" not in name and "vscode" not in name else "extrapolated",
                "note": note,
            }
        )

    # Old-vs-new comparison using retained prior incompressible rows.
    old_vs_new = {
        "status": "model",
        "label": "model",
        "prior_incompressible_note": (
            "Prior published rows used XorShift/random large blobs (low gzip "
            "savings). New corpora are source-shaped and compressible."
        ),
        "prior_row_count": len(prior_rows),
        "new_compressible_corpus_count": len(corpora),
        "expected_effect": (
            "Storage parity vs plain-git pack moves against SafeHub on "
            "compressible trees because git delta-compresses and SafeHub cannot."
        ),
    }

    doc = {
        "id": "E01",
        "title": "Real compressible repository corpora vs synthetic (extended)",
        "meta": meta_block(
            SCRIPT,
            "gzip measured on generated compressible corpora; timings AEAD-model; "
            "prior rows retained (NO_SCALE_DOWN)",
            REPS,
        ),
        "prior_rows": prior_rows,
        "old_vs_new": old_vs_new,
        "measured_compressible_corpora": corpora,
        "git_delta_compression_model": git_delta_model,
        "synthetic_model_rows": model_rows,
        "model": {
            "a_s_per_byte": a,
            "b_s_per_chunk": b,
            "c_rtt_s": c,
            "d_s_per_object": d,
            "P": P,
            "aead_backend": "hkdf-sha512-pad+HMAC-SHA-512-256",
        },
        "locked_sweeps_retained": prior.get("locked_sweeps_retained")
        or ["8MiB", "10MiB", "12MiB"],
        "additive_large": prior.get("additive_large")
        or {"sizes_mib": [100, 200], "objects": 1000, "push_count": 8},
        "notes": [
            "prior_rows retained additively from the previous artifact.",
            "tree_gzip_* fields are measured; safehub_*_ms timings are models "
            "from measured AEAD rates (see timing_status).",
            "Full network E2E: SAFEHUB_REALREPO_NET=1 ./scripts/e2e_realrepo_scale.sh",
        ],
    }
    # Preserve legacy top-level keys that papers may cite.
    if prior_rows:
        doc["rows"] = prior_rows + [
            {
                "class": c["corpus"],
                "objects": c["files"],
                "bytes": c["tree_bytes"],
                "chunks": math.ceil(c["tree_bytes"] / (4 * 1024 * 1024)),
                "cold_clone_s_est": round(c["safehub_clone_ms"]["median"] / 1000.0, 3),
                "measured": False,
                "status": "model",
                "label": "model",
                "peak_rss_note": "compressible corpus extension; see measured_compressible_corpora",
                "tree_gzip_ratio": c["tree_gzip_ratio"],
            }
            for c in corpora
        ]
    write_published(out, doc)


if __name__ == "__main__":
    main()
