#!/usr/bin/env python3
"""Shared helpers for AuthGuard scanner reliability (audit-driven)."""

from __future__ import annotations

import math
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

# CWE defaults by finding category (CVE only when version fingerprinted).
FINDING_CWE_MAP: Dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "request smuggling": "CWE-444",
    "http smuggling": "CWE-444",
    "cache poisoning": "CWE-524",
    "auth timing": "CWE-208",
    "timing": "CWE-208",
    "enumeration": "CWE-208",
    "ssrf": "CWE-918",
    "clickjacking": "CWE-1021",
    "security headers": "CWE-693",
    "open redirect": "CWE-601",
    "host header": "CWE-644",
    "idor": "CWE-639",
    "path traversal": "CWE-22",
    "lfi": "CWE-22",
    "jwt": "CWE-347",
    "mass assignment": "CWE-915",
    "ssti": "CWE-1336",
    "graphql": "CWE-200",
    "xxe": "CWE-611",
    "subdomain takeover": "CWE-350",
}

SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 1,
}

# root_cause_id -> merge clickjacking into headers when frame protection missing
ROOT_CAUSE_MISSING_FRAME = "missing_frame_protection"


def canary(prefix: str = "KG", length: int = 12) -> str:
    return f"{prefix}{uuid.uuid4().hex[:length]}"


def lookup_cwe(title: str, module: str = "", default: str = "") -> str:
    blob = f"{title} {module}".lower()
    for key, cwe in FINDING_CWE_MAP.items():
        if key in blob:
            return cwe
    return default or "CWE-Unknown"


def trim_outliers(values: Sequence[float], fraction: float = 0.10) -> List[float]:
    if not values:
        return []
    xs = sorted(float(v) for v in values)
    n = len(xs)
    if n < 5:
        return xs
    k = max(1, int(n * fraction))
    return xs[k : n - k] if n > 2 * k else xs


def mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def pearson_r(x: Sequence[float], y: Sequence[float]) -> float:
    if len(x) < 2 or len(x) != len(y):
        return 0.0
    mx, my = mean(x), mean(y)
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    den_x = math.sqrt(sum((a - mx) ** 2 for a in x))
    den_y = math.sqrt(sum((b - my) ** 2 for b in y))
    if den_x == 0 or den_y == 0:
        return 0.0
    return num / (den_x * den_y)


def mann_whitney_u(
    sample_a: Sequence[float],
    sample_b: Sequence[float],
) -> Tuple[float, float]:
    """Return (U statistic, two-sided p-value approximation)."""
    a = list(sample_a)
    b = list(sample_b)
    if len(a) < 3 or len(b) < 3:
        return 0.0, 1.0

    ranked: List[Tuple[float, str]] = []
    for v in a:
        ranked.append((v, "a"))
    for v in b:
        ranked.append((v, "b"))
    ranked.sort(key=lambda t: t[0])

    # Average ranks for ties
    i = 0
    rank_sum_a = 0.0
    n = len(ranked)
    while i < n:
        j = i
        while j + 1 < n and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg_rank = (i + j + 2) / 2.0  # 1-based ranks
        for k in range(i, j + 1):
            if ranked[k][1] == "a":
                rank_sum_a += avg_rank
        i = j + 1

    na, nb = len(a), len(b)
    u_a = rank_sum_a - na * (na + 1) / 2.0
    u_b = na * nb - u_a
    u = min(u_a, u_b)

    mu = na * nb / 2.0
    sigma = math.sqrt(na * nb * (na + nb + 1) / 12.0)
    if sigma == 0:
        return u, 1.0
    z = abs((u - mu) / sigma)
    # two-sided normal approximation
    p = math.erfc(z / math.sqrt(2.0))
    return u, min(1.0, max(0.0, p))


def compute_risk_score(findings: Sequence[Any], min_confidence: float = 0.7) -> int:
    total = 0
    for f in findings:
        conf = float(getattr(getattr(f, "exploit", None), "confidence", 0.0) or 0.0)
        if not getattr(getattr(f, "exploit", None), "confirmed", False):
            continue
        if conf < min_confidence:
            continue
        w = SEVERITY_WEIGHT.get(getattr(f, "severity", ""), 0)
        total += w
    return min(100, total)


def finding_root_cause_id(f: Any) -> str:
    ex = getattr(f, "exploit", None)
    rc = getattr(ex, "root_cause_id", "") if ex else ""
    if rc:
        return rc
    title = (getattr(f, "title", "") or "").lower()
    mod = (getattr(f, "module", "") or "").lower()
    if "clickjacking" in title or mod == "clickjacking":
        return ROOT_CAUSE_MISSING_FRAME
    if "security headers" in title and "clickjacking" in (getattr(ex, "proof", "") or "").lower():
        return ROOT_CAUSE_MISSING_FRAME
    if "frame" in title or "x-frame" in (getattr(ex, "proof", "") or "").lower():
        return ROOT_CAUSE_MISSING_FRAME
    return f"{mod}:{title[:80]}"


def dedup_findings(findings: List[Any]) -> List[Any]:
    """Merge findings sharing (affected_url, root_cause_id); keep higher severity."""
    from authguard_core import SEV_ORDER

    seen: Dict[Tuple[str, str], Any] = {}
    annex: List[Any] = []

    for f in findings:
        conf = float(getattr(getattr(f, "exploit", None), "confidence", 0.0) or 0.0)
        if conf <= 0.0:
            annex.append(f)
            continue

        aff = (getattr(getattr(f, "exploit", None), "affected", "") or getattr(f, "title", "")).rstrip("/")
        key = (aff, finding_root_cause_id(f))
        if key not in seen:
            seen[key] = f
            continue

        existing = seen[key]
        try:
            if SEV_ORDER.index(f.severity) < SEV_ORDER.index(existing.severity):
                existing, f = f, existing
                seen[key] = existing
        except ValueError:
            pass

        ex = existing.exploit
        other = f.exploit
        merged_proof = (ex.proof or "").strip()
        extra = (other.proof or "").strip()
        if extra and extra not in merged_proof:
            ex.proof = merged_proof + "\n---\nMerged evidence:\n" + extra
        ex.secondary_signal = (
            (getattr(ex, "secondary_signal", "") or "")
            + ("; " if getattr(ex, "secondary_signal", "") else "")
            + (getattr(other, "secondary_signal", "") or f.module)
        ).strip("; ")

    return list(seen.values()) + annex
