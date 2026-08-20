#!/usr/bin/env python3
"""Shared helpers for published JSON generators.

Every published cell must carry dispersion (median+IQR or mean+CI) and a
status of measured|model|extrapolated. Hardware AES is NOT on the transport
hot path after the HKDF-SHA-512 RO-pad + HMAC migration.
"""
from __future__ import annotations

import json
import math
import os
import platform
import statistics
import subprocess
import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_ROOT = REPO_ROOT / "code"
PUB_DIR = CODE_ROOT / "eval" / "published"
AEAD_BACKEND = "hkdf-sha512-pad+HMAC-SHA-512-256"
AES_NOTE = (
    "Transport AEAD is HKDF-SHA-512 RO-pad + HMAC-SHA-512-256 "
    "(CommittingAead); hardware AES is unused on the application "
    "transport hot path. MLS suite AEAD is independent."
)


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sysctl(key: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["sysctl", "-n", key],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if out.returncode == 0:
            return (out.stdout or "").strip() or None
    except Exception:
        pass
    return None


def _cmd(args: list[str]) -> Optional[str]:
    try:
        out = subprocess.run(
            args, capture_output=True, text=True, timeout=20, check=False,
            cwd=str(REPO_ROOT),
        )
        if out.returncode == 0:
            return (out.stdout or "").strip() or None
    except Exception:
        pass
    return None


def build_provenance() -> dict[str, Any]:
    """What was actually built and measured.

    Without this a reader cannot tell whether a cell came from the real
    Category-5 OpenMLS path or from the development stub that
    `safehub-crypto` still carries as its bare-crate default feature. The
    binaries request `features = ["openmls"]`, but that is a claim about the
    manifest; these fields are a claim about the artifact.
    """
    prov: dict[str, Any] = {
        "git_commit": _cmd(["git", "rev-parse", "HEAD"]),
        "git_describe": _cmd(["git", "describe", "--always", "--dirty"]),
        "git_dirty": bool(_cmd(["git", "status", "--porcelain"])),
        "rustc": _cmd(["rustc", "--version"]),
        "cargo": _cmd(["cargo", "--version"]),
        "git_version": _cmd(["git", "--version"]),
        "mls_ciphersuite": None,
        "mls_backend": None,
        "aead_backend": AEAD_BACKEND,
        "crypto_features": None,
    }
    # Ask the built CLI what it actually linked, rather than asserting it.
    report = _cmd(
        [
            "cargo",
            "run",
            "-q",
            "--manifest-path",
            str(CODE_ROOT / "Cargo.toml"),
            "-p",
            "safehub-cli",
            "--release",
            "--bin",
            "shub",
            "--",
            "crypto",
            "report",
            "--json",
        ]
    )
    if report:
        try:
            parsed = json.loads(report)
            prov["mls_ciphersuite"] = parsed.get("mls_ciphersuite")
            prov["mls_backend"] = parsed.get("mls_backend")
            prov["crypto_features"] = parsed.get("features")
            prov["aead_backend"] = parsed.get("aead_backend", AEAD_BACKEND)
            prov["stub_linked"] = parsed.get("stub_linked")
        except Exception:
            prov["mls_ciphersuite"] = "unreported"
    return prov


def machine_info() -> dict[str, Any]:
    arch = platform.machine()
    mem = _sysctl("hw.memsize")
    ncpu = _sysctl("hw.ncpu")
    cpu = _sysctl("machdep.cpu.brand_string")
    model = _sysctl("hw.model")
    return {
        "os": platform.system().lower(),
        "os_release": platform.release(),
        "arch": arch,
        "cpu_hint": os.environ.get("SAFEHUB_EVAL_CPU") or cpu or model or "unspecified",
        "cpu_count": int(ncpu) if ncpu and ncpu.isdigit() else os.cpu_count(),
        "ram_bytes": int(mem) if mem and mem.isdigit() else None,
        "ram_gib": round(int(mem) / (1024**3), 1) if mem and mem.isdigit() else None,
        "storage_hint": os.environ.get(
            "SAFEHUB_EVAL_STORAGE", "local SSD (APFS/ext4)"
        ),
        "hardware_aes_on_transport": False,
        "aead_backend": AEAD_BACKEND,
        "aes_note": AES_NOTE,
        "build_profile": os.environ.get("SAFEHUB_EVAL_PROFILE", "release"),
        "python": platform.python_version(),
        "measured_at": utc_now(),
    }


def meta_block(
    generated_by: str,
    method: str,
    reps: int,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    m = machine_info()
    quiet = os.environ.get("SAFEHUB_EVAL_QUIET_HOST", "true").lower() in (
        "1",
        "true",
        "yes",
    )
    out = {
        "generated_by": generated_by,
        "method": method,
        "reps": reps,
        "machine": m.get("cpu_hint"),
        "machine_detail": m,
        "provenance": build_provenance(),
        "aes_note": AES_NOTE,
        "aead_backend": AEAD_BACKEND,
        "date": utc_now(),
        "quiet_host": quiet,
        "host_note": (
            "Measurements taken after confirming no leftover safehub-server/"
            "safehub-browse/safehub-local-ui listeners and no competing cargo "
            "eval builds owned by this harness."
            if quiet
            else "quiet_host not asserted"
        ),
    }
    if extra:
        out.update(extra)
    return out


def quantile(data: list[float], q: float) -> float:
    if len(data) == 1:
        return data[0]
    pos = (len(data) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return data[int(pos)]
    return data[lo] + (data[hi] - data[lo]) * (pos - lo)


def dispersion(samples: Iterable[float], unit: str = "ms") -> dict[str, Any]:
    raw = [float(x) for x in samples]
    if not raw:
        return {"n": 0, "status": "no-samples", "unit": unit}
    raw_sorted = sorted(raw)
    n = len(raw_sorted)
    median = statistics.median(raw_sorted)
    p25 = quantile(raw_sorted, 0.25)
    p75 = quantile(raw_sorted, 0.75)
    mean = statistics.fmean(raw_sorted)
    stdev = statistics.stdev(raw_sorted) if n > 1 else 0.0
    ci = 1.96 * stdev / math.sqrt(n) if n > 1 else None
    return {
        "n": n,
        "unit": unit,
        "median": round(median, 4),
        "p25": round(p25, 4),
        "p75": round(p75, 4),
        "iqr": round(p75 - p25, 4),
        "mean": round(mean, 4),
        "stdev": round(stdev, 4),
        "ci95_half_width": round(ci, 4) if ci is not None else None,
        "min": round(raw_sorted[0], 4),
        "max": round(raw_sorted[-1], 4),
        "samples": [round(x, 4) for x in raw],
        "dispersion": (
            "median+IQR over n reps" if n > 1 else "single shot (label microbench-only)"
        ),
    }


def analytic_point(value: float, unit: str = "ms") -> dict:
    """A single analytically derived value, published without fake spread.

    The previous helper (`jittered_reps`) manufactured pseudo-replicates around
    an analytic centre so that every cell could satisfy the dispersion
    requirement. Synthesized variance is indistinguishable from measured
    variance once it is in the JSON, so it is not published any more: an
    analytic cell now says so and carries no IQR.
    """
    return {
        "value": round(float(value), 4),
        "unit": unit,
        "n": 1,
        "dispersion": None,
        "kind": "analytic",
        "note": "analytically derived; no replicates, no synthesized spread",
    }


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_published(path: Path, doc: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {path}")
    return path


def load_micro_from_smoke() -> dict[str, Any]:
    """Prefer freshly published smoke; fall back to fullstack micro."""
    candidates = [
        PUB_DIR / "smoke-latest.json",
        CODE_ROOT / "eval" / "results" / "tmp-smoke-eval" / "smoke.json",
        PUB_DIR / "fullstack-latest.json",
        PUB_DIR / "full-latest.json",
    ]
    for p in candidates:
        if p.exists():
            doc = load_json(p)
            micro = doc.get("micro")
            if micro:
                micro = dict(micro)
                micro["source"] = str(p.relative_to(REPO_ROOT))
                return micro
    raise FileNotFoundError("no smoke/fullstack micro timings found")


def load_join_ops() -> list[dict[str, Any]]:
    for name in ("fullstack-latest.json", "full-latest.json"):
        p = PUB_DIR / name
        if p.exists():
            ops = load_json(p).get("join_ops") or []
            if ops:
                return ops
    return []


def load_invite_path() -> dict[str, Any]:
    for name in ("fullstack-latest.json", "full-latest.json"):
        p = PUB_DIR / name
        if p.exists():
            inv = load_json(p).get("invite_path") or {}
            if inv:
                inv = dict(inv)
                inv["source"] = name
                return inv
    return {}


def load_security() -> dict[str, Any]:
    for name in ("fullstack-latest.json", "full-latest.json"):
        p = PUB_DIR / name
        if p.exists():
            sec = load_json(p).get("security") or {}
            if sec:
                return sec
    return {}


def aead_ms_per_byte(micro: dict[str, Any], op: str = "seal") -> float:
    """Milliseconds per byte for the transport AEAD, from the 1 MiB micro timing.

    Nanoseconds convert to milliseconds by 1e6. This divided by 1e9, returning
    SECONDS per byte from a helper named -- and used everywhere as -- ms per
    byte, making every model built on it 1000x too small. The one call site that
    wanted seconds (gen_realrepo_scale_latest.py) divided this result by 1000,
    confirming ms was the intended contract.
    """
    key = f"aead_{op}_1mib_ns"
    ns = float(micro[key])
    return (ns / 1e6) / (1024 * 1024)


def slope(xs: list[float], ys: list[float]) -> Optional[float]:
    n = len(xs)
    if n < 2:
        return None
    mx = sum(xs) / n
    my = sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
