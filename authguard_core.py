from __future__ import annotations

import json
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from http.cookiejar import CookieJar
from typing import Any, Dict, Optional, Tuple, Union


SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

def _sha256_12(value: str) -> str:
    import hashlib

    return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()[:12]


def redact_sensitive(text: str) -> str:
    import re

    if not text:
        return ""

    patterns = [
        re.compile(r'(?i)\b(authorization)\s*:\s*([^\r\n]+)'),
        re.compile(r'(?i)\b(cookie)\s*:\s*([^\r\n]+)'),
        re.compile(r'(?i)\b(set-cookie)\s*:\s*([^\r\n]+)'),
        re.compile(r'(?i)\b(x-api-key|api[-_]?key|client[-_]?secret|secret)\s*:\s*([^\r\n]+)'),
        re.compile(r'(?i)\b(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b'),
        re.compile(r'(?i)\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b'),
    ]

    def _mask_header(match: re.Match) -> str:
        name = match.group(1)
        val = match.group(2)
        return f"{name}: [REDACTED sha256:{_sha256_12(val)} len:{len(val)}]"

    redacted = text
    redacted = patterns[0].sub(_mask_header, redacted)
    redacted = patterns[1].sub(_mask_header, redacted)
    redacted = patterns[2].sub(_mask_header, redacted)
    redacted = patterns[3].sub(_mask_header, redacted)
    redacted = patterns[4].sub(lambda m: f"[REDACTED_JWT sha256:{_sha256_12(m.group(1))}]", redacted)
    redacted = patterns[5].sub(lambda m: f"[REDACTED_AWS_KEY sha256:{_sha256_12(m.group(1))}]", redacted)
    return redacted


C: Dict[str, str] = {
    "bg0": "#0b0f14",
    "bg1": "#0f1620",
    "bg2": "#111a26",
    "bg3": "#151f2e",
    "bg4": "#1a2638",
    "border": "#2a3a52",
    "border2": "#3a4d69",
    "bg_hover": "#1d2a3f",
    "t1": "#e8eef6",
    "t2": "#b9c7db",
    "t3": "#8ea2bf",
    "t4": "#6f84a6",
    "red": "#ff4d5a",
    "orange": "#ff9b3d",
    "yellow": "#ffd166",
    "green": "#2ee59d",
    "cyan": "#4fd8ff",
    "cyan2": "#9be8ff",
    "blue": "#6ea8fe",
    "purple": "#c084fc",
    "CRITICAL": "#ff4d5a",
    "HIGH": "#ff9b3d",
    "MEDIUM": "#ffd166",
    "LOW": "#4fd8ff",
    "INFO": "#b9c7db",
}


@dataclass
class ExploitResult:
    confirmed: bool = False
    success: bool = False
    access_level: str = ""
    confidence: float = 0.0
    technique: str = ""
    affected: str = ""
    request: str = ""
    response: str = ""
    proof: str = ""
    root_cause_id: str = ""
    confirmed_method: str = ""
    secondary_signal: str = ""
    # Pen-test weakpoint location
    location_summary: str = ""
    location_url: str = ""
    location_method: str = ""
    location_path: str = ""
    location_parameter: str = ""
    location_header: str = ""
    component: str = ""
    # Controlled exploitation analysis
    evidence_grade: str = ""
    exploitation_analysis: str = ""
    attacker_scenario: str = ""
    blast_radius: str = ""
    reproduction: str = ""
    remediation: str = ""


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    module: str
    cvss: str = ""
    cve: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    exploit: ExploitResult = field(default_factory=ExploitResult)


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    content: bytes
    elapsed: timedelta

    @property
    def text(self) -> str:
        charset = "utf-8"
        content_type = self.headers.get("content-type") or self.headers.get("Content-Type") or ""
        if "charset=" in content_type:
            charset = content_type.split("charset=")[-1].split(";")[0].strip() or charset
        try:
            return self.content.decode(charset, errors="replace")
        except Exception:
            return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class StealthSession:
    def __init__(self, stealth_level: int = 2, timeout: Union[int, float] = 12):
        self.stealth_level = int(stealth_level or 0)
        self.timeout = float(timeout or 12)
        self.stopped = False
        self.last_error = ""
        self._cookies = CookieJar()
        self._ssl_context = ssl.create_default_context()
        self._ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        ]

    def stop(self) -> None:
        self.stopped = True

    def _base_headers(self) -> Dict[str, str]:
        ua = random.choice(self._ua_pool)
        h = {
            "User-Agent": ua,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Accept-Encoding": "gzip, deflate",
        }
        if self.stealth_level >= 3:
            h["DNT"] = "1"
            h["Sec-Fetch-Site"] = "none"
            h["Sec-Fetch-Mode"] = "navigate"
            h["Sec-Fetch-Dest"] = "document"
        return h

    def _maybe_delay(self) -> None:
        if self.stealth_level <= 0:
            return
        if self.stealth_level == 1:
            time.sleep(random.uniform(0.05, 0.15))
        elif self.stealth_level == 2:
            time.sleep(random.uniform(0.1, 0.35))
        else:
            time.sleep(random.uniform(0.15, 0.6))

    def _opener(self, allow_redirects: bool) -> urllib.request.OpenerDirector:
        handlers = [
            urllib.request.HTTPCookieProcessor(self._cookies),
            urllib.request.HTTPSHandler(context=self._ssl_context),
        ]
        if not allow_redirects:
            handlers.append(_NoRedirect())
        return urllib.request.build_opener(*handlers)

    def _build_url(self, url: str, params: Optional[Dict[str, Any]]) -> str:
        if not params:
            return url
        parsed = urllib.parse.urlparse(url)
        existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for k, v in params.items():
            existing[k] = [v] if not isinstance(v, (list, tuple)) else list(v)
        new_query = urllib.parse.urlencode(existing, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        json_body: Optional[Any] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[HttpResponse]:
        if self.stopped:
            return None
        self.last_error = ""

        method = method.upper().strip()
        url = self._build_url(url, params)
        headers = self._base_headers()
        if extra_headers:
            headers.update({str(k): str(v) for k, v in extra_headers.items()})

        body: Optional[bytes] = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, bytes):
                body = data
            elif isinstance(data, str):
                body = data.encode("utf-8")
            elif isinstance(data, dict):
                body = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                body = str(data).encode("utf-8")

        req = urllib.request.Request(url=url, data=body, method=method, headers=headers)
        self._maybe_delay()

        t0 = time.perf_counter()
        try:
            opener = self._opener(allow_redirects=allow_redirects)
            with opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read() or b""
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                enc = hdrs.get("content-encoding", "").lower()
                if "gzip" in enc:
                    import gzip

                    raw = gzip.decompress(raw)
                elif "deflate" in enc:
                    import zlib

                    try:
                        raw = zlib.decompress(raw)
                    except Exception:
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                elapsed = timedelta(seconds=(time.perf_counter() - t0))
                return HttpResponse(
                    url=getattr(resp, "url", url),
                    status_code=int(getattr(resp, "status", 0)),
                    headers=hdrs,
                    content=raw,
                    elapsed=elapsed,
                )
        except urllib.error.HTTPError as e:
            try:
                raw = e.read() or b""
            except Exception:
                raw = b""
            hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
            elapsed = timedelta(seconds=(time.perf_counter() - t0))
            return HttpResponse(
                url=getattr(e, "url", url),
                status_code=int(getattr(e, "code", 0) or 0),
                headers=hdrs,
                content=raw,
                elapsed=elapsed,
            )
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            return None

    def get(self, url: str, *, extra_headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[HttpResponse]:
        params = kwargs.pop("params", None)
        allow_redirects = bool(kwargs.pop("allow_redirects", True))
        return self._request(
            "GET",
            url,
            params=params,
            extra_headers=extra_headers,
            allow_redirects=allow_redirects,
        )

    def post(self, url: str, *, extra_headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[HttpResponse]:
        params = kwargs.pop("params", None)
        data = kwargs.pop("data", None)
        json_body = kwargs.pop("json", None)
        allow_redirects = bool(kwargs.pop("allow_redirects", True))
        return self._request(
            "POST",
            url,
            params=params,
            data=data,
            json_body=json_body,
            extra_headers=extra_headers,
            allow_redirects=allow_redirects,
        )
