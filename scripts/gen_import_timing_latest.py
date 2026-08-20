#!/usr/bin/env python3
"""Eval E15 — import timing for an existing git repository."""
from __future__ import annotations

import math
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import (  # noqa: E402
    PUB_DIR,
    aead_ms_per_byte,
    dispersion,
    analytic_point,
    load_micro_from_smoke,
    meta_block,
    write_published,
)

REPS = 5
SCRIPT = "scripts/gen_import_timing_latest.py"


def make_sample_repo(root: Path, files: int, bytes_target: int) -> dict:
    import os
    import subprocess

    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "--template="], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "eval@safehub.local"], cwd=repo, check=True
    )
    subprocess.run(
        ["git", "config", "user.name", "SafeHub Eval"], cwd=repo, check=True
    )
    written = 0
    for i in range(files):
        p = repo / "src" / f"f{i:04d}.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        chunk = (f"line {i}\n" * 40).encode()
        p.write_bytes(chunk)
        written += len(chunk)
        if written >= bytes_target:
            break
    # Pad if needed.
    while written < bytes_target:
        p = repo / "src" / f"pad_{written}.bin"
        need = min(65536, bytes_target - written)
        p.write_bytes(b"A" * need)
        written += need
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "import corpus"], cwd=repo, check=True)
    # Count objects.
    out = subprocess.run(
        ["git", "count-objects", "-v"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    objs = 0
    for line in out.stdout.splitlines():
        if line.startswith("count:"):
            objs += int(line.split()[1])
        if line.startswith("in-pack:"):
            objs += int(line.split()[1])
    return {"path": repo, "bytes": written, "files": files, "objects": objs}


def main():
    micro = load_micro_from_smoke()
    seal = aead_ms_per_byte(micro, "seal")

    # Keep the scratch tree inside the workspace so sandboxed runs can git-init.
    scratch_root = PUB_DIR.parent / "results" / "tmp-import-timing"
    scratch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="safehub-import-", dir=str(scratch_root)) as tmp:
        meta = make_sample_repo(Path(tmp), files=200, bytes_target=4 * 1024 * 1024)
        # Measured: time a plain git bundle (stand-in for packing phase of import).
        bundle = Path(tmp) / "repo.bundle"
        pack_samples = []
        for _ in range(REPS):
            if bundle.exists():
                bundle.unlink()
            t0 = time.perf_counter()
            import subprocess

            subprocess.run(
                ["git", "bundle", "create", str(bundle), "--all"],
                cwd=meta["path"],
                check=True,
                capture_output=True,
            )
            pack_samples.append((time.perf_counter() - t0) * 1000.0)
        pack_ms = dispersion(pack_samples, "ms")
        bundle_bytes = bundle.stat().st_size

    # Model: import = pack/read history + seal all objects as SafeHub ciphertext + Welcome.
    seal_ms = seal * meta["bytes"] + 40.0
    total_model = pack_ms["median"] + seal_ms

    cells = [
        {
            "phase": "git_bundle_pack",
            "description": "Pack existing git history (measured local bundle)",
            "repo_files": meta["files"],
            "repo_bytes": meta["bytes"],
            "bundle_bytes": bundle_bytes,
            "wall_ms": pack_ms,
            "status": "measured",
            "label": "measured",
        },
        {
            "phase": "safehub_seal_import",
            "description": "Seal imported objects under CommittingAead",
            "wall_ms": analytic_point(seal_ms, "ms"),
            "status": "model",
            "label": "model",
            "note": "AEAD-rate × working-tree bytes + control-plane constant.",
        },
        {
            "phase": "end_to_end_import",
            "description": "bundle pack + seal + initial push model",
            "wall_ms": analytic_point(total_model, "ms"),
            "status": "model",
            "label": "model",
            "note": (
                "sit import (or equiv) end-to-end; issues/PRs metadata out of "
                "scope for migration claims."
            ),
        },
    ]

    # Extrapolated larger repos.
    for mib, status in [(50, "model"), (500, "extrapolated")]:
        b = mib * 1024 * 1024
        t = seal * b + pack_ms["median"] * (mib / 4.0)
        cells.append(
            {
                "phase": f"end_to_end_import_{mib}mib",
                "repo_mib": mib,
                "wall_ms": analytic_point(t, "ms"),
                "status": status,
                "label": status,
            }
        )

    doc = {
        "id": "E15",
        "title": "Import timing for an existing git repository",
        "meta": meta_block(
            SCRIPT,
            "measured git bundle pack on 4 MiB sample; seal/import modeled",
            REPS,
        ),
        "sample_repo": {
            "files": meta["files"],
            "bytes": meta["bytes"],
            "objects_approx": meta["objects"],
        },
        "cells": cells,
        "notes": [
            "Adoption claims should cite this import cost; forge issues/PRs "
            "metadata migration remains out of scope.",
        ],
    }
    write_published(PUB_DIR / "import-timing-latest.json", doc)


if __name__ == "__main__":
    main()
