#!/usr/bin/env python3
"""
AuthGuard Pro v4.1 — Behavioral Baseline Engine
Learns normal application behavior, then detects anomalies.
Mirrors how elite pentesters identify subtle vulnerabilities through deviation analysis.
"""

import re, json, hashlib, statistics
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict


@dataclass
class ResponseFingerprint:
    """Fingerprint of a normal response for comparison."""
    url_pattern: str
    status_code: int
    content_length: int
    content_length_range: Tuple[int, int]
    headers: Dict[str, str]
    header_keys: List[str]
    body_hash: str
    body_structure: str
    response_time: float
    response_time_range: Tuple[float, float]
    error_indicators: List[str]
    sample_count: int = 1


@dataclass
class AnomalyFinding:
    """A detected behavioral anomaly."""
    url: str
    anomaly_type: str
    severity: str
    description: str
    baseline_value: Any
    observed_value: Any
    deviation_score: float
    evidence: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class BehavioralBaseline:
    """
    Builds a behavioral baseline of the target application,
    then detects deviations that may indicate vulnerabilities.
    """

    ANOMALY_SIGNATURES = {
        "status_code_change": {
            "severity": "MEDIUM",
            "description": "Endpoint returns unexpected status code — may indicate broken access control or error handling issues"
        },
        "content_length_spike": {
            "severity": "HIGH",
            "description": "Response size significantly differs from baseline — may indicate data leakage or verbose error messages"
        },
        "response_time_anomaly": {
            "severity": "HIGH",
            "description": "Response time significantly differs from baseline — may indicate time-based injection or resource exhaustion"
        },
        "header_absence": {
            "severity": "LOW",
            "description": "Expected security headers missing from response"
        },
        "header_injection": {
            "severity": "MEDIUM",
            "description": "Unexpected headers in response — may indicate proxy/cache manipulation"
        },
        "body_structure_change": {
            "severity": "HIGH",
            "description": "Response structure differs from baseline — may indicate different code path execution (injection, bypass)"
        },
        "error_indicator_present": {
            "severity": "HIGH",
            "description": "Error indicators present in response that were absent in baseline"
        },
        "redirect_loop": {
            "severity": "MEDIUM",
            "description": "Unexpected redirect behavior — may indicate open redirect or auth bypass"
        },
        "cache_behavior_change": {
            "severity": "MEDIUM",
            "description": "Caching behavior differs from baseline — may indicate cache poisoning"
        }
    }

    def __init__(self, http_session, target: str):
        self.http = http_session
        self.target = target.rstrip("/")
        self.baselines: Dict[str, ResponseFingerprint] = {}
        self.anomalies: List[AnomalyFinding] = []
        self._training_urls: List[str] = []

    def _simplify_url(self, url: str) -> str:
        """Convert URL to a pattern for grouping similar endpoints."""
        pattern = re.sub(r'/\d+', '/:id', url)
        pattern = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/:uuid', pattern, flags=re.I)
        pattern = re.sub(r'/[0-9a-f]{32,}', '/:hash', pattern, flags=re.I)
        pattern = re.sub(r'/[^/]+@[^/]+', '/:email', pattern)
        return pattern

    def _extract_body_structure(self, body: str) -> str:
        """Extract structural fingerprint of response body."""
        structure = body
        structure = re.sub(r'>[^<]{3,}<', '>TEXT<', structure)
        structure = re.sub(r'>\d+<', '>NUM<', structure)
        structure = re.sub(r'https?://[^\s"\'<>]+', 'URL', structure)
        structure = re.sub(r'\s+', ' ', structure)
        return structure[:2000]

    def _hash_body(self, body: str) -> str:
        """Create hash of response body."""
        return hashlib.sha256(body.encode()).hexdigest()[:16]

    def _extract_error_indicators(self, body: str, headers: Dict) -> List[str]:
        """Extract potential error indicators from response."""
        indicators = []
        body_lower = body.lower()

        error_patterns = [
            r'error', r'exception', r'warning', r'fatal', r'syntax error',
            r'stack trace', r'traceback', r'debug', r'php error',
            r'sql error', r'database error', r'internal server error',
            r'not found', r'forbidden', r'unauthorized'
        ]

        for pattern in error_patterns:
            if re.search(pattern, body_lower):
                indicators.append(pattern)

        if re.search(r'File ".+?", line \d+', body):
            indicators.append("python_traceback")
        if re.search(r'at .+?\(.+?\.java:\d+\)', body):
            indicators.append("java_stack_trace")
        if re.search(r'\.php on line \d+', body):
            indicators.append("php_error")

        return indicators

    def train(self, urls: List[str], samples_per_url: int = 3):
        """Build baseline by making multiple requests to each URL."""
        self._training_urls = urls

        for url in urls:
            if self.http.stopped:
                break

            url_pattern = self._simplify_url(url)
            responses = []

            for _ in range(samples_per_url):
                r = self.http.get(url)
                if r:
                    responses.append(r)

            if not responses:
                continue

            lengths = [len(r.content) for r in responses]
            times = [r.elapsed.total_seconds() if hasattr(r, 'elapsed') else 0.5 for r in responses]

            status_codes = [r.status_code for r in responses]
            common_status = max(set(status_codes), key=status_codes.count)

            baseline_response = responses[0]
            body = baseline_response.text or ""

            headers = dict(baseline_response.headers)
            header_keys = list(headers.keys())

            fingerprint = ResponseFingerprint(
                url_pattern=url_pattern,
                status_code=common_status,
                content_length=statistics.median(lengths),
                content_length_range=(min(lengths), max(lengths)),
                headers=headers,
                header_keys=header_keys,
                body_hash=self._hash_body(body),
                body_structure=self._extract_body_structure(body),
                response_time=statistics.median(times),
                response_time_range=(min(times), max(times)),
                error_indicators=self._extract_error_indicators(body, headers),
                sample_count=len(responses)
            )

            self.baselines[url_pattern] = fingerprint

    def analyze(self, url: str, response,
                test_description: str = "") -> List[AnomalyFinding]:
        """Compare a response against the baseline and report anomalies."""
        if not response:
            return []

        url_pattern = self._simplify_url(url)
        baseline = self.baselines.get(url_pattern)

        if not baseline:
            return []

        findings = []
        body = response.text or ""
        current_length = len(response.content)
        current_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0.5
        current_headers = dict(response.headers)
        current_hash = self._hash_body(body)
        current_structure = self._extract_body_structure(body)
        current_errors = self._extract_error_indicators(body, current_headers)

        # 1. Status code anomaly
        if response.status_code != baseline.status_code:
            deviation = 1.0
            findings.append(AnomalyFinding(
                url=url,
                anomaly_type="status_code_change",
                severity=self.ANOMALY_SIGNATURES["status_code_change"]["severity"],
                description=self.ANOMALY_SIGNATURES["status_code_change"]["description"],
                baseline_value=baseline.status_code,
                observed_value=response.status_code,
                deviation_score=deviation,
                evidence=f"Baseline: HTTP {baseline.status_code}, Observed: HTTP {response.status_code}"
            ))

        # 2. Content length anomaly
        min_len, max_len = baseline.content_length_range
        len_margin = max(max_len * 0.5, 500)
        if current_length < min_len - len_margin or current_length > max_len + len_margin:
            deviation = min(abs(current_length - baseline.content_length) / max(baseline.content_length, 1), 1.0)
            findings.append(AnomalyFinding(
                url=url,
                anomaly_type="content_length_spike",
                severity=self.ANOMALY_SIGNATURES["content_length_spike"]["severity"],
                description=self.ANOMALY_SIGNATURES["content_length_spike"]["description"],
                baseline_value=f"{min_len}-{max_len} bytes",
                observed_value=f"{current_length} bytes",
                deviation_score=deviation,
                evidence=f"Baseline range: {min_len}-{max_len}B, Observed: {current_length}B (delta: {current_length - baseline.content_length}B)"
            ))

        # 3. Response time anomaly
        min_time, max_time = baseline.response_time_range
        time_margin = max(max_time * 2, 2.0)
        if current_time > max_time + time_margin:
            deviation = min((current_time - baseline.response_time) / max(baseline.response_time, 0.1), 1.0)
            findings.append(AnomalyFinding(
                url=url,
                anomaly_type="response_time_anomaly",
                severity=self.ANOMALY_SIGNATURES["response_time_anomaly"]["severity"],
                description=self.ANOMALY_SIGNATURES["response_time_anomaly"]["description"],
                baseline_value=f"{min_time:.2f}-{max_time:.2f}s",
                observed_value=f"{current_time:.2f}s",
                deviation_score=deviation,
                evidence=f"Baseline: {min_time:.2f}-{max_time:.2f}s, Observed: {current_time:.2f}s (delta: {current_time - baseline.response_time:.2f}s)"
            ))

        # 4. Body structure change
        if current_hash != baseline.body_hash:
            if self._structure_differs(baseline.body_structure, current_structure):
                findings.append(AnomalyFinding(
                    url=url,
                    anomaly_type="body_structure_change",
                    severity=self.ANOMALY_SIGNATURES["body_structure_change"]["severity"],
                    description=self.ANOMALY_SIGNATURES["body_structure_change"]["description"],
                    baseline_value="consistent structure",
                    observed_value="different structure",
                    deviation_score=0.8,
                    evidence="Response HTML structure differs from baseline — different code path may have executed"
                ))

        # 5. Error indicators
        new_errors = [e for e in current_errors if e not in baseline.error_indicators]
        if new_errors:
            findings.append(AnomalyFinding(
                url=url,
                anomaly_type="error_indicator_present",
                severity=self.ANOMALY_SIGNATURES["error_indicator_present"]["severity"],
                description=self.ANOMALY_SIGNATURES["error_indicator_present"]["description"],
                baseline_value=f"known errors: {baseline.error_indicators}",
                observed_value=f"new errors: {new_errors}",
                deviation_score=0.9,
                evidence=f"New error indicators: {', '.join(new_errors)}"
            ))

        # 6. Header anomalies
        missing_headers = [h for h in baseline.header_keys if h not in current_headers]
        if missing_headers:
            findings.append(AnomalyFinding(
                url=url,
                anomaly_type="header_absence",
                severity=self.ANOMALY_SIGNATURES["header_absence"]["severity"],
                description=self.ANOMALY_SIGNATURES["header_absence"]["description"],
                baseline_value=f"headers: {baseline.header_keys}",
                observed_value=f"missing: {missing_headers}",
                deviation_score=0.3,
                evidence=f"Headers present in baseline but missing now: {missing_headers}"
            ))

        self.anomalies.extend(findings)
        return findings

    def _structure_differs(self, baseline: str, current: str) -> bool:
        """Check if body structures are significantly different."""
        if len(baseline) == 0 and len(current) == 0:
            return False
        if len(baseline) == 0 or len(current) == 0:
            return True

        max_len = max(len(baseline), len(current))
        if max_len == 0:
            return False

        diff_count = sum(1 for a, b in zip(baseline[:500], current[:500]) if a != b)
        diff_count += abs(len(baseline[:500]) - len(current[:500]))

        return (diff_count / min(len(baseline[:500]), 500)) > 0.3

    def get_high_confidence_anomalies(self, min_deviation: float = 0.7) -> List[AnomalyFinding]:
        """Get anomalies with high deviation scores."""
        return [a for a in self.anomalies if a.deviation_score >= min_deviation]

    def get_anomaly_report(self) -> Dict:
        """Generate comprehensive anomaly report."""
        by_type = defaultdict(list)
        for a in self.anomalies:
            by_type[a.anomaly_type].append(a)

        return {
            "total_anomalies": len(self.anomalies),
            "high_confidence": len(self.get_high_confidence_anomalies()),
            "by_type": {k: len(v) for k, v in by_type.items()},
            "findings": [
                {
                    "url": a.url,
                    "type": a.anomaly_type,
                    "severity": a.severity,
                    "deviation": round(a.deviation_score, 3),
                    "description": a.description,
                    "evidence": a.evidence
                }
                for a in sorted(self.anomalies, key=lambda x: x.deviation_score, reverse=True)
            ]
        }