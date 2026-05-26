#!/usr/bin/env python3
"""
AuthGuard Pro v4.1 — Adaptive Evasion Engine
Auto-morphs payloads when WAF blocks are detected.
Mirrors how elite red teams bypass modern WAFs.
"""

import re, random, base64, urllib.parse, html
import json
from typing import Any, List, Dict, Tuple, Optional


class AdaptiveEvasion:
    """
    When a probe is blocked, automatically tries encoding mutations
    until one succeeds or all options are exhausted.
    """

    # WAF block indicators
    BLOCK_SIGNS = [
        "403 forbidden", "406 not acceptable", "429 too many requests",
        "503 service unavailable", "blocked", "waf", "cloudflare",
        "security check", "suspicious", "attack detected", "mod_security",
        "incapsula", "akamai", "sucuri", "blocked by", "access denied",
        "request rejected", "unauthorized request", "bad request"
    ]

    def __init__(self, http_session, *, allow_evasion: bool = False):
        self.http = http_session
        self.allow_evasion = bool(allow_evasion)
        self._evasion_log = []
        self._success_patterns = {}

    def is_blocked(self, response) -> Tuple[bool, str]:
        """Determine if response indicates WAF blocking."""
        if not response:
            return True, "No response (connection blocked)"

        text = (response.text or "").lower()
        headers = str(dict(response.headers)).lower()
        combined = text + headers

        # Check status codes
        if response.status_code in [403, 406, 429, 501, 503]:
            for sign in self.BLOCK_SIGNS:
                if sign in combined:
                    return True, f"WAF block detected: {sign}"
            if response.status_code in [403, 406] and len(response.content) < 2048:
                return True, f"HTTP {response.status_code} with minimal content"

        # Check for WAF-specific headers
        waf_headers = ["cf-ray", "x-sucuri-id", "x-iinfo", "x-akamai",
                       "x-waf-status", "x-amzn-waf", "x-mod-security"]
        for wh in waf_headers:
            if wh in headers:
                return True, f"WAF header detected: {wh}"

        return False, ""

    def encode_payload(self, payload: str, technique: str) -> str:
        """Apply a specific encoding technique."""
        if technique == "url_encode":
            return urllib.parse.quote(payload, safe='')
        elif technique == "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        elif technique == "url_encode_plus":
            return urllib.parse.quote_plus(payload)
        elif technique == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif technique == "base64_urlsafe":
            return base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
        elif technique == "html_entities":
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif technique == "html_entities_hex":
            return ''.join(f'&#x{ord(c):x};' for c in payload)
        elif technique == "unicode_normalize":
            return payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("'", "\\u0027").replace('"', "\\u0022")
        else:
            return payload

    # Ordered by stealth vs effectiveness
    EVASION_TECHNIQUES = [
        "url_encode",
        "double_url_encode",
        "unicode_normalize",
        "html_entities_hex",
        "base64_urlsafe",
    ]

    def evade_request(self, method: str, url: str,
                      payload: str = None,
                      param_name: str = None,
                      extra_headers: dict = None,
                      **request_kwargs) -> Tuple[Optional[Any], str, str]:
        """
        Try original request, then auto-evade if blocked.
        Returns: (response, technique_used, evidence)
        """
        # Try original first
        if method.upper() == "GET":
            r = self.http.get(url, extra_headers=extra_headers, **request_kwargs)
        else:
            r = self.http.post(url, extra_headers=extra_headers, **request_kwargs)

        blocked, reason = self.is_blocked(r)
        if not blocked:
            return r, "original", "No WAF interference"

        if not self.allow_evasion:
            return r, "disabled", f"WAF interference detected ({reason}). Evasion attempts are disabled."

        self._evasion_log.append(f"Blocked ({reason}), attempting evasion...")

        # Try each evasion technique
        for technique in self.EVASION_TECHNIQUES:
            if self.http.stopped:
                return None, "aborted", "Scan stopped"

            encoded = self.encode_payload(payload or "", technique)

            # Rebuild URL or data with encoded payload
            if param_name and payload:
                if method.upper() == "GET":
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    if param_name in qs:
                        qs[param_name] = [encoded]
                        new_query = urllib.parse.urlencode(qs, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    else:
                        test_url = url
                    r = self.http.get(test_url, extra_headers=extra_headers, **request_kwargs)
                else:
                    new_data = request_kwargs.get('data', {})
                    if isinstance(new_data, dict):
                        new_data = dict(new_data)
                        new_data[param_name] = encoded
                    new_kwargs = dict(request_kwargs)
                    new_kwargs['data'] = new_data
                    r = self.http.post(url, extra_headers=extra_headers, **new_kwargs)
            else:
                ev_headers = dict(extra_headers or {})
                ev_headers["X-Evasion-Test"] = technique
                if method.upper() == "GET":
                    r = self.http.get(url, extra_headers=ev_headers, **request_kwargs)
                else:
                    r = self.http.post(url, extra_headers=ev_headers, **request_kwargs)

            blocked, reason = self.is_blocked(r)
            if not blocked:
                self._success_patterns[url.split('/')[2]] = technique
                return r, technique, f"Bypassed WAF using {technique}"

        return r, "failed", "All evasion techniques exhausted"

    def get_evasion_report(self) -> List[str]:
        """Return log of evasion attempts."""
        return self._evasion_log
