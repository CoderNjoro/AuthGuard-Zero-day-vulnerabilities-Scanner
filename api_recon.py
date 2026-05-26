#!/usr/bin/env python3
"""
AuthGuard Pro v4.1 — API Reconnaissance Module
Parses JavaScript files, discovers hidden endpoints, parameters, and API keys.
Mirrors how elite pentesters map modern SPAs and API-driven applications.
"""

import re, json, urllib.parse, math, hashlib
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse


class JSApiRecon:
    """
    Deep JavaScript analysis for API discovery.
    Extracts endpoints, parameters, API keys, and authentication patterns.
    """

    # Regex patterns for extracting API artifacts from JS
    PATTERNS = {
        "api_endpoint": re.compile(
            r'["\']((?:https?://[^"\']+)?(?:/api|/graphql|/rest|/v\d+|/svc)[^"\']*)["\']',
            re.I
        ),
        "fetch_url": re.compile(
            r'(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["\']([^"\']+)["\']',
            re.I
        ),
        "route_path": re.compile(
            r'(?:path|route|url)\s*:\s*["\']([^"\']+)["\']',
            re.I
        ),
        "template_url": re.compile(
            r'[`"\']([^`"\']*\$\{[^}]+\}[^`"\']*)[`"\']',
            re.I
        ),
        "query_param": re.compile(
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
            re.I
        ),
        "post_param": re.compile(
            r'(?:body|data|params)\s*:\s*\{([^}]+)\}',
            re.I
        ),
        "form_field": re.compile(
            r'(?:name|id)\s*=\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
            re.I
        ),
        "api_key": re.compile(
            r'(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?key|client[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']',
            re.I
        ),
        "bearer_token": re.compile(
            r'(?:bearer|authorization)\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,})["\']',
            re.I
        ),
        "jwt_hardcoded": re.compile(
            r'["\'](eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)["\']',
            re.I
        ),
        "aws_key": re.compile(
            r'(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})',
            re.I
        ),
        "private_key": re.compile(
            r'(?:private[_-]?key|secret[_-]?key)\s*[:=]\s*["\']([a-zA-Z0-9+/=]{20,})["\']',
            re.I
        ),
        "graphql_query": re.compile(
            r'(?:query|mutation)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{',
            re.I
        ),
        "graphql_endpoint": re.compile(
            r'["\']([^"\']*graphql[^"\']*)["\']',
            re.I
        ),
        "websocket_url": re.compile(
            r'(?:ws|wss)://[^"\']+',
            re.I
        ),
        "admin_path": re.compile(
            r'["\']([^"\']*(?:admin|manage|dashboard|panel|control)[^"\']*)["\']',
            re.I
        ),
        "debug_path": re.compile(
            r'["\']([^"\']*(?:debug|test|dev|staging|local)[^"\']*)["\']',
            re.I
        ),
    }

    def __init__(self, http_session, target: str):
        self.http = http_session
        self.target = target.rstrip("/")
        self.parsed = urlparse(target)
        self.discovered = {
            "endpoints": set(),
            "parameters": set(),
            "api_keys": [],
            "tokens": [],
            "graphql_queries": set(),
            "websocket_urls": set(),
            "js_files": [],
            "source_map_files": [],
        }
        self._analyzed_urls = set()

    def _sha256_12(self, value: str) -> str:
        return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()[:12]

    def _entropy(self, value: str) -> float:
        if not value:
            return 0.0
        freq = {}
        for ch in value:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(value)
        ent = 0.0
        for c in freq.values():
            p = c / n
            ent -= p * math.log2(p)
        return ent

    def _looks_like_secret(self, value: str, context: str) -> Tuple[bool, float]:
        if not value:
            return False, 0.0
        v = value.strip()
        if len(v) < 16:
            return False, 0.0
        if v.lower() in {"changeme", "test", "testing", "example", "sample", "dummy", "secret"}:
            return False, 0.0
        if re.fullmatch(r"[0-9]+", v):
            return False, 0.0
        if re.fullmatch(r"[0-9a-f]{16,}", v, flags=re.I):
            base = 0.45
        else:
            base = 0.55
        ent = self._entropy(v)
        ent_score = min(max((ent - 3.2) / 1.2, 0.0), 1.0)
        ctx = (context or "").lower()
        ctx_bonus = 0.0
        for kw in ["apikey", "api_key", "client_secret", "secret", "token", "authorization", "bearer"]:
            if kw in ctx:
                ctx_bonus = 0.15
                break
        confidence = min(base + ent_score * 0.45 + ctx_bonus, 1.0)
        return confidence >= 0.65, confidence

    def _mask_context(self, context: str, value: str) -> str:
        if not context:
            return ""
        if not value:
            return context[:240]
        return (context.replace(value, "[REDACTED]"))[:240]

    def _record_secret_candidate(self, kind: str, value: str, context: str, source_url: str, *, token_type: str = "") -> Optional[Dict]:
        ok, confidence = self._looks_like_secret(value, context)
        if not ok:
            return None
        item = {
            "kind": kind,
            "hash": self._sha256_12(value),
            "len": len(value),
            "confidence": round(confidence, 3),
            "context": self._mask_context(context, value),
            "source": source_url,
        }
        if token_type:
            item["type"] = token_type
        if kind == "api_key":
            self.discovered["api_keys"].append(item)
        else:
            self.discovered["tokens"].append(item)
        return item

    def discover_js_files(self, page_html: str) -> List[str]:
        """Find all JavaScript file references in HTML."""
        js_urls = []

        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', page_html, re.I):
            url = match.group(1)
            full_url = urljoin(self.target, url)
            js_urls.append(full_url)

        for match in re.finditer(r'import\s+["\']([^"\']+)["\']', page_html, re.I):
            url = match.group(1)
            full_url = urljoin(self.target, url)
            js_urls.append(full_url)

        for match in re.finditer(r'import\s*\(\s*["\']([^"\']+)["\']\s*\)', page_html, re.I):
            url = match.group(1)
            full_url = urljoin(self.target, url)
            js_urls.append(full_url)

        for match in re.finditer(r'//# sourceMappingURL=([^\s]+)', page_html, re.I):
            url = match.group(1)
            full_url = urljoin(self.target, url)
            self.discovered["source_map_files"].append(full_url)

        return list(set(js_urls))

    def analyze_js_content(self, js_text: str, source_url: str) -> Dict:
        """Deep analysis of JavaScript content for API artifacts."""
        findings = {
            "endpoints": set(),
            "parameters": set(),
            "api_keys": [],
            "tokens": [],
            "graphql_queries": set(),
            "websocket_urls": set(),
            "interesting_paths": set(),
        }

        for pattern_name in ["api_endpoint", "fetch_url", "route_path", "template_url"]:
            pattern = self.PATTERNS[pattern_name]
            for match in pattern.finditer(js_text):
                url = match.group(1)
                if url.startswith("http"):
                    findings["endpoints"].add(url)
                elif url.startswith("/"):
                    findings["endpoints"].add(f"{self.parsed.scheme}://{self.parsed.netloc}{url}")
                elif url.startswith("./") or url.startswith("../"):
                    findings["endpoints"].add(urljoin(source_url, url))
                elif not url.startswith(("data:", "javascript:", "#")):
                    findings["endpoints"].add(urljoin(self.target, url))

        for match in self.PATTERNS["query_param"].finditer(js_text):
            findings["parameters"].add(match.group(1))

        for match in self.PATTERNS["post_param"].finditer(js_text):
            content = match.group(1)
            for field_match in re.finditer(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:', content):
                findings["parameters"].add(field_match.group(1))

        for match in self.PATTERNS["form_field"].finditer(js_text):
            findings["parameters"].add(match.group(1))

        for match in self.PATTERNS["api_key"].finditer(js_text):
            raw = match.group(1)
            ctx = js_text[max(0, match.start()-80):match.end()+80]
            item = self._record_secret_candidate("api_key", raw, ctx, source_url)
            if item:
                findings["api_keys"].append(item)

        for match in self.PATTERNS["bearer_token"].finditer(js_text):
            raw = match.group(1)
            ctx = js_text[max(0, match.start()-80):match.end()+80]
            item = self._record_secret_candidate("token", raw, ctx, source_url, token_type="bearer")
            if item:
                findings["tokens"].append(item)

        for match in self.PATTERNS["jwt_hardcoded"].finditer(js_text):
            raw = match.group(1)
            ctx = js_text[max(0, match.start()-80):match.end()+80]
            item = self._record_secret_candidate("token", raw, ctx, source_url, token_type="jwt")
            if item:
                findings["tokens"].append(item)

        for match in self.PATTERNS["aws_key"].finditer(js_text):
            raw = match.group(0)
            ctx = js_text[max(0, match.start()-80):match.end()+80]
            item = self._record_secret_candidate("api_key", raw, ctx, source_url)
            if item:
                findings["api_keys"].append(item)

        for match in self.PATTERNS["graphql_query"].finditer(js_text):
            findings["graphql_queries"].add(match.group(1))

        for match in self.PATTERNS["graphql_endpoint"].finditer(js_text):
            findings["endpoints"].add(match.group(1))

        for match in self.PATTERNS["websocket_url"].finditer(js_text):
            findings["websocket_urls"].add(match.group(0))

        for match in self.PATTERNS["admin_path"].finditer(js_text):
            findings["interesting_paths"].add(match.group(1))

        for match in self.PATTERNS["debug_path"].finditer(js_text):
            findings["interesting_paths"].add(match.group(1))

        return findings

    def analyze_source_map(self, map_url: str) -> Dict:
        """Analyze source map for original code and more endpoints."""
        findings = {
            "original_files": [],
            "endpoints": set(),
            "hardcoded_strings": []
        }

        try:
            r = self.http.get(map_url)
            if r and r.status_code == 200:
                try:
                    source_map = json.loads(r.text)
                    if "sources" in source_map:
                        findings["original_files"] = source_map["sources"]

                    if "sourcesContent" in source_map:
                        for content in source_map["sourcesContent"]:
                            if isinstance(content, str):
                                sub_findings = self.analyze_js_content(content, map_url)
                                findings["endpoints"].update(sub_findings["endpoints"])
                                findings["hardcoded_strings"].extend(
                                    list(sub_findings["api_keys"]) +
                                    list(sub_findings["tokens"])
                                )
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        return findings

    def run_full_recon(self, page_html: str = None) -> Dict:
        """
        Execute full JavaScript reconnaissance.
        If page_html is provided, starts from that content.
        Otherwise fetches the target homepage first.
        """
        if page_html is None:
            r = self.http.get(self.target)
            if r:
                page_html = r.text
            else:
                return self.discovered

        js_files = self.discover_js_files(page_html)
        self.discovered["js_files"] = js_files

        for js_url in js_files:
            if js_url in self._analyzed_urls:
                continue
            self._analyzed_urls.add(js_url)

            try:
                r = self.http.get(js_url)
                if r and r.status_code == 200:
                    findings = self.analyze_js_content(r.text, js_url)

                    self.discovered["endpoints"].update(findings["endpoints"])
                    self.discovered["parameters"].update(findings["parameters"])
                    self.discovered["api_keys"].extend(findings["api_keys"])
                    self.discovered["tokens"].extend(findings["tokens"])
                    self.discovered["graphql_queries"].update(findings["graphql_queries"])
                    self.discovered["websocket_urls"].update(findings["websocket_urls"])
            except Exception:
                continue

        for map_url in self.discovered["source_map_files"]:
            map_findings = self.analyze_source_map(map_url)
            self.discovered["endpoints"].update(map_findings["endpoints"])

        return {
            "endpoints": sorted(list(self.discovered["endpoints"])),
            "parameters": sorted(list(self.discovered["parameters"])),
            "api_keys": self.discovered["api_keys"],
            "tokens": self.discovered["tokens"],
            "graphql_queries": sorted(list(self.discovered["graphql_queries"])),
            "websocket_urls": sorted(list(self.discovered["websocket_urls"])),
            "js_files": self.discovered["js_files"],
            "source_map_files": self.discovered["source_map_files"],
        }

    def get_fuzzable_endpoints(self) -> List[Dict]:
        """
        Get endpoints ready for fuzzing/parameter discovery.
        Returns endpoints with discovered parameters templated.
        """
        results = []
        params = list(self.discovered["parameters"])

        for endpoint in self.discovered["endpoints"]:
            parsed = urlparse(endpoint)
            if parsed.query:
                results.append({
                    "url": endpoint,
                    "method": "GET",
                    "params": urllib.parse.parse_qs(parsed.query)
                })
            else:
                if params:
                    query = "&".join(f"{p}=FUZZ" for p in params[:5])
                    fuzz_url = f"{endpoint}?{query}"
                    results.append({
                        "url": fuzz_url,
                        "method": "GET",
                        "params": {p: "FUZZ" for p in params[:5]}
                    })
                else:
                    results.append({
                        "url": endpoint,
                        "method": "GET",
                        "params": {}
                    })

        return results
