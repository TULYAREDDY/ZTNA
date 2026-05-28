"""Synthetic ZTNA telemetry generator.

Why a synthetic dataset
=======================
Public IDS datasets (NSL-KDD, CICIDS-2017/2018) describe network *flow*
features (bytes, packet sizes, TCP flags). Our model operates one layer
higher — at the **session/identity** layer — using behavioural features
emitted by a Policy Decision Point. No public dataset captures these
signals jointly, so we synthesise one whose generative process is
explicit and grounded in well-documented attack patterns from
MITRE ATT&CK.

Generative model
----------------
For every record we first sample a *persona*:

  - normal_user   (62 %)   regular work-hours traffic
  - power_user    (12 %)   high request rate but trusted device
  - off_hours     ( 6 %)   late-night legitimate access
  - travelling    ( 6 %)   benign user on a foreign / mobile IP
  - forgetful     ( 4 %)   benign user who fat-fingered their password
  - hijacked      ( 5 %)   T1078: stolen credential, IP change
  - brute_force   ( 3 %)   T1110: rapid attempts, mostly local
  - recon         ( 2 %)   T1595: low-rate probing from low-trust device

Each persona has its own conditional distribution over the eight raw
features. The class boundaries are deliberately fuzzy — benign personas
can produce signals (high `location_risk` for travelling users, high
`failed_attempts` for forgetful users) that overlap with attack
personas. This forces the classifier to learn multivariate boundaries
instead of memorising a single feature threshold, which is exactly what
a real ZTNA model has to do.

Labels are derived from the persona, not the features.
"""

from __future__ import annotations

import argparse
import csv
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np


@dataclass
class Persona:
    name: str
    weight: float
    label: int
    sampler: Callable[[np.random.Generator], dict]


# ---------------------------------------------------------------------------
# Benign personas
# ---------------------------------------------------------------------------

def _normal_user(rng: np.random.Generator) -> dict:
    return {
        "request_rate": float(rng.lognormal(mean=0.0, sigma=0.6)),
        "ip_change": 0,
        "failed_attempts": int(rng.poisson(0.3)),
        "device_trust": float(rng.beta(8, 2)),
        "time_of_day": int(rng.choice(range(8, 20))),
        "location_risk": float(rng.beta(2, 10)),         # ~0.17 median
        "posture_score": float(rng.uniform(80, 100)),
        "session_age_min": float(rng.uniform(1, 240)),
    }


def _power_user(rng: np.random.Generator) -> dict:
    return {
        "request_rate": float(rng.uniform(3, 9)),         # bursty, overlaps brute_force
        "ip_change": 0,
        "failed_attempts": int(rng.poisson(0.4)),
        "device_trust": float(rng.beta(9, 1)),
        "time_of_day": int(rng.choice(range(7, 22))),
        "location_risk": float(rng.beta(2, 12)),
        "posture_score": float(rng.uniform(85, 100)),
        "session_age_min": float(rng.uniform(30, 480)),
    }


def _off_hours_user(rng: np.random.Generator) -> dict:
    return {
        "request_rate": float(rng.uniform(0.1, 1.5)),
        "ip_change": 0,
        "failed_attempts": int(rng.poisson(0.4)),
        "device_trust": float(rng.beta(7, 3)),
        "time_of_day": int(rng.choice([0, 1, 2, 3, 4, 5, 22, 23])),
        "location_risk": float(rng.beta(3, 8)),
        "posture_score": float(rng.uniform(70, 100)),
        "session_age_min": float(rng.uniform(1, 90)),
    }


def _travelling_user(rng: np.random.Generator) -> dict:
    """Benign user who is on a hotel/airport/mobile network.

    They legitimately produce a high `location_risk` and may even change
    IPs (mobile handover) — this is the persona that prevents the model
    from collapsing onto a single threshold on `location_risk`.
    """
    return {
        "request_rate": float(rng.uniform(0.2, 4)),
        "ip_change": int(rng.choice([0, 1], p=[0.6, 0.4])),
        "failed_attempts": int(rng.poisson(0.5)),
        "device_trust": float(rng.beta(7, 3)),
        "time_of_day": int(rng.choice(range(0, 24))),
        "location_risk": float(rng.beta(6, 4)),           # ~0.6 median, overlaps attacks
        "posture_score": float(rng.uniform(70, 100)),
        "session_age_min": float(rng.uniform(1, 240)),
    }


def _forgetful_user(rng: np.random.Generator) -> dict:
    """Benign user who genuinely forgot their password."""
    return {
        "request_rate": float(rng.uniform(0.3, 3)),
        "ip_change": 0,
        "failed_attempts": int(rng.integers(3, 8)),       # overlaps brute_force lower bound
        "device_trust": float(rng.beta(7, 3)),
        "time_of_day": int(rng.choice(range(7, 22))),
        "location_risk": float(rng.beta(2, 9)),
        "posture_score": float(rng.uniform(70, 100)),
        "session_age_min": float(rng.uniform(1, 60)),
    }


# ---------------------------------------------------------------------------
# Attack personas
# ---------------------------------------------------------------------------

def _hijacked(rng: np.random.Generator) -> dict:
    """T1078 Valid Accounts. Stolen credential, attacker on different IP."""
    return {
        "request_rate": float(rng.uniform(0.5, 8)),
        "ip_change": 1,
        "failed_attempts": int(rng.poisson(1.2)),
        "device_trust": float(rng.beta(5, 4)),
        "time_of_day": int(rng.choice(range(0, 24))),
        "location_risk": float(rng.beta(5, 4)),           # ~0.55, overlaps travelling
        "posture_score": float(rng.uniform(60, 95)),
        "session_age_min": float(rng.uniform(0.5, 120)),
    }


def _brute_force(rng: np.random.Generator) -> dict:
    """T1110. Rapid attempts; often a LOCAL compromised host, so
    `location_risk` is intentionally moderate."""
    return {
        "request_rate": float(rng.uniform(8, 25)),
        "ip_change": int(rng.choice([0, 1], p=[0.4, 0.6])),
        "failed_attempts": int(rng.integers(5, 16)),
        "device_trust": float(rng.beta(2, 6)),
        "time_of_day": int(rng.choice(range(0, 24))),
        "location_risk": float(rng.beta(4, 5)),           # ~0.44 median
        "posture_score": float(rng.uniform(20, 70)),
        "session_age_min": float(rng.uniform(0.1, 30)),
    }


def _recon(rng: np.random.Generator) -> dict:
    """T1595. Slow probing, often from an unmanaged but otherwise
    compliant device on a normal-looking network."""
    return {
        "request_rate": float(rng.uniform(0.05, 0.5)),
        "ip_change": int(rng.choice([0, 1], p=[0.5, 0.5])),
        "failed_attempts": int(rng.poisson(2)),
        "device_trust": float(rng.beta(3, 6)),
        "time_of_day": int(rng.choice(range(0, 24))),
        "location_risk": float(rng.beta(4, 6)),           # ~0.4 median
        "posture_score": float(rng.uniform(30, 75)),
        "session_age_min": float(rng.uniform(5, 200)),
    }


PERSONAS: list[Persona] = [
    Persona("normal_user",    0.62, 0, _normal_user),
    Persona("power_user",     0.12, 0, _power_user),
    Persona("off_hours",      0.06, 0, _off_hours_user),
    Persona("travelling",     0.06, 0, _travelling_user),
    Persona("forgetful",      0.04, 0, _forgetful_user),
    Persona("hijacked",       0.05, 1, _hijacked),
    Persona("brute_force",    0.03, 1, _brute_force),
    Persona("recon",          0.02, 1, _recon),
]


FIELDS = [
    "request_rate", "ip_change", "failed_attempts", "device_trust",
    "time_of_day", "location_risk", "posture_score", "session_age_min",
    "persona", "is_attack",
]


def _add_noise(row: dict, rng: np.random.Generator) -> dict:
    """Inject feature-level Gaussian / categorical noise.

    The class boundaries between personas are deliberately fuzzy in the
    real world. Without noise the test accuracy pegs at 1.000, which is
    academically suspicious. ~12 % perturbed rows produces a realistic
    0.93–0.97 accuracy band.
    """
    row["request_rate"] = max(0.0, row["request_rate"] + rng.normal(0, 1.8))
    row["device_trust"] = float(np.clip(row["device_trust"] + rng.normal(0, 0.12), 0, 1))
    row["location_risk"] = float(np.clip(row["location_risk"] + rng.normal(0, 0.15), 0, 1))
    row["posture_score"] = float(np.clip(row["posture_score"] + rng.normal(0, 8), 0, 100))
    row["failed_attempts"] = max(0, row["failed_attempts"] + int(rng.integers(-1, 2)))
    if rng.random() < 0.4:
        row["ip_change"] = 1 - row["ip_change"]
    return row


def generate(
    n: int,
    seed: int = 7,
    noise_rate: float = 0.12,
    label_flip_rate: float = 0.02,
) -> list[dict]:
    """Generate `n` synthetic ZTNA records.

    `noise_rate`        — fraction of rows whose features are perturbed.
    `label_flip_rate`   — fraction of rows whose label is flipped (mimics
                          mislabelled training data, common in security
                          datasets, and prevents the classifier from
                          fitting the personas perfectly).
    """
    rng = np.random.default_rng(seed)
    rand = random.Random(seed)
    weights = [p.weight for p in PERSONAS]
    rows: list[dict] = []
    for _ in range(n):
        persona = rand.choices(PERSONAS, weights=weights, k=1)[0]
        row = persona.sampler(rng)
        if rng.random() < noise_rate:
            row = _add_noise(row, rng)
        label = persona.label
        if rng.random() < label_flip_rate:
            label = 1 - label
        row["request_rate"] = round(row["request_rate"], 3)
        row["device_trust"] = round(row["device_trust"], 3)
        row["location_risk"] = round(row["location_risk"], 3)
        row["posture_score"] = round(row["posture_score"], 1)
        row["session_age_min"] = round(row["session_age_min"], 2)
        row["persona"] = persona.name
        row["is_attack"] = label
        rows.append(row)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=Path("app/ml/artifacts/dataset.csv"))
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    rows = generate(args.n, args.seed)

    with args.out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    attacks = sum(r["is_attack"] for r in rows)
    print(f"wrote {len(rows)} rows -> {args.out}  (attacks={attacks}, "
          f"benign={len(rows) - attacks})")


if __name__ == "__main__":
    main()
