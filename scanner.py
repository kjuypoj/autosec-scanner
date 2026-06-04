import asyncio
import ssl
import socket
import json
import time
import re
import ipaddress
import base64
import logging
import argparse
import sys
import binascii
import os
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl, urlencode
from typing import Optional, Tuple, List, Dict, Any, Callable
import httpx
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup  # M5 크롤링용

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_SAFE_MODE = True
DEFAULT_PORT_WORKERS = 100
HTTP_TIMEOUT = 15.0
SSL_HANDSHAKE_TIMEOUT = 5.0
PORT_SCAN_TIMEOUT = 2.0
SQLI_BOOLEAN_DIFF_THRESHOLD = 50
SQLI_TIME_DELAY_THRESHOLD = 4.0
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
COMMON_FUZZ_WORDLIST = [
    ".env", ".git/", ".git/config", "backup.zip", "backup.tar.gz",
    "admin/", "config.php", "phpinfo.php", ".svn/", ".DS_Store",
]
XSS_PAYLOADS = [
    "<svg/onload=alert(1)>", "\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>", "%3Csvg%2Fonload%3Dalert(1)%3E",
]
SQLI_ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "';"]
SQLI_BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("\" AND 1=1--", "\" AND 1=2--")
]
SQLI_TIME_PAYLOADS = ["'; WAITFOR DELAY '0:0:5'--", "\"; WAITFOR DELAY '0:0:5'--"]
INTERNAL_IP_TARGETS = [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"
]

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("scanner")


class RateLimiter:
    def __init__(self, rate: float) -> None:
        self._rate = rate
        self._capacity = rate
        self._tokens = rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delta = now - self._last
            self._tokens = min(self._capacity, self._tokens + delta * self._rate)
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                now = time.monotonic()
                delta = now - self._last
                self._tokens = min(self._capacity, self._tokens + delta * self._rate)
            self._last = now
            self._tokens -= 1


class ScannerContext:
    def __init__(
        self,
        target: str,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        safe_mode: bool = DEFAULT_SAFE_MODE,
        verify_ssl: bool = True
    ) -> None:
        self.target = target
        self.safe_mode = safe_mode
        self.verify_ssl = verify_ssl
        self.rate_limiter = RateLimiter(rate_limit)
        self._session: Optional[httpx.AsyncClient] = None
        self._session_lock = asyncio.Lock()
        self.nvd_semaphore = asyncio.Semaphore(5)

    async def get_session(self) -> httpx.AsyncClient:
        async with self._session_lock:
            if self._session is None:
                self._session = httpx.AsyncClient(
                    timeout=HTTP_TIMEOUT, verify=self.verify_ssl, follow_redirects=True
                )
            return self._session

    async def close(self) -> None:
        async with self._session_lock:
            if self._session:
                try:
                    await self._session.aclose()
                except httpx.HTTPError:
                    logger.exception("Error closing HTTP session")
                finally:
                    self._session = None


def is_valid_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_host_port(url: str, default_port: int = 443) -> Tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Cannot parse host from {url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port

async def rate_limited_request(
    ctx: ScannerContext, method: str, url: str, **kwargs: Any
) -> Tuple[Optional[int], Dict[str, str], str, str]:
    await ctx.rate_limiter.acquire()
    session = await ctx.get_session()
    timeout = kwargs.pop("timeout", HTTP_TIMEOUT)
    try:
        response = await session.request(method, url, timeout=timeout, **kwargs)
        return response.status_code, dict(response.headers), response.text, str(response.url)
    except httpx.HTTPError as e:
        # 👇👇 logger.exception을 logger.warning으로 수정 👇👇
        logger.warning(f"Connection failed on {method} {url} (Reason: {type(e).__name__})")
        return None, {}, "", url

async def ssl_tls_scan(ctx: ScannerContext, host: str, port: int = 443) -> Dict[str, Any]:
    result = {"protocol": None, "cipher": None, "vulnerable": False}

    def attempt(min_v: ssl.TLSVersion, max_v: ssl.TLSVersion) -> Tuple[Optional[str], Optional[str]]:
        ctx_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_ssl.minimum_version = min_v
        ctx_ssl.maximum_version = max_v
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=SSL_HANDSHAKE_TIMEOUT) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    v = ssock.version()
                    c = ssock.cipher()[0] if ssock.cipher() else None
                    return v, c
        except (ssl.SSLError, socket.error):
            return None, None

    probes = [
        (ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3),
        (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
        (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ]
    for min_v, max_v in probes:
        version, cipher = await asyncio.to_thread(attempt, min_v, max_v)
        if version:
            result["protocol"] = version
            result["cipher"] = cipher
            if version.startswith("SSL") or (cipher and any(x in cipher.upper() for x in ("RC4", "DES"))):
                result["vulnerable"] = True
            break
    return result


async def nvd_search_cve(ctx: ScannerContext, keyword: str) -> List[str]:
    await ctx.rate_limiter.acquire()
    await ctx.rate_limiter.acquire()
    NVD_API_KEY = "A4ED3142-D55F-F111-836C-0EBF96DE670D" 
    
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    headers = {"apiKey": NVD_API_KEY} 
    
    async with ctx.nvd_semaphore:
        try:
            session = await ctx.get_session()
            # 3. get 요청에 headers 파라미터를 추가해서 보냅니다.
            resp = await session.get(NVD_API_URL, params=params, headers=headers, timeout=HTTP_TIMEOUT)
            
            if resp.status_code != 200:
                # 에러 코드가 나면 디버깅을 위해 살짝 출력해 줍니다.
                logger.debug(f"NVD API Error: {resp.status_code} for keyword {keyword}")
                return []
            data = resp.json()
            return [
                item["cve"]["id"]
                for item in data.get("vulnerabilities", [])
                if item.get("cve", {}).get("id")
            ]
        except (httpx.HTTPError, json.JSONDecodeError):
            logger.exception("NVD API error for %s", keyword)
            return []


def _write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


async def write_poc_file(path: str, content: str) -> None:
    await asyncio.to_thread(_write_file, path, content)


def port_scan_single(host: str, port: int, timeout: float = PORT_SCAN_TIMEOUT) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except socket.timeout:
                banner = ""
        return True, banner
    except (socket.timeout, socket.error):
        return False, ""


async def port_scan_banner(
    ctx: ScannerContext,
    host: str,
    port_range: Tuple[int, int] = (1, 1024),
    workers: int = DEFAULT_PORT_WORKERS
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(workers)
    lock = asyncio.Lock()

    async def scan_one(p: int) -> None:
        async with sem:
            await ctx.rate_limiter.acquire()
            open_, banner = await asyncio.get_running_loop().run_in_executor(
                None, port_scan_single, host, p
            )
            if open_:
                token = banner.split()[0] if banner else ""
                cves = await nvd_search_cve(ctx, token) if token else []
                async with lock:
                    results.append({"port": p, "banner": banner, "cve": cves})

    tasks = [asyncio.create_task(scan_one(p)) for p in range(port_range[0], port_range[1] + 1)]
    await asyncio.gather(*tasks)
    return results


async def security_headers_check(ctx: ScannerContext, url: str) -> Dict[str, Any]:
    status, headers, _, final = await rate_limited_request(ctx, "GET", url)
    missing = [h for h in ("X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security") if h not in headers]
    poc_files: List[str] = []
    if "X-Frame-Options" not in headers and final:
        host_tag = re.sub(r"[^a-zA-Z0-9_-]", "_", urlparse(final).hostname or "target")[:50]
        fn = f"clickjacking_poc_{host_tag}.html"
        poc = (
            "<!doctype html><html><head><title>Clickjacking PoC</title></head>"
            f"<body><iframe src=\"{final}\" style=\"border:none;width:100%;height:100vh;\"></iframe></body></html>"
        )
        try:
            await write_poc_file(fn, poc)
            poc_files.append(fn)
        except OSError:
            logger.exception("Failed to write PoC %s", fn)
    return {"status": status, "missing_headers": missing, "poc_files": poc_files}


async def cors_cookie_check(ctx: ScannerContext, url: str) -> Dict[str, Any]:
    headers = {"Origin": "https://evil.com"}
    status, resp_h, _, _ = await rate_limited_request(ctx, "GET", url, headers=headers)
    acao = resp_h.get("Access-Control-Allow-Origin")
    acac = resp_h.get("Access-Control-Allow-Credentials")
    cors_vuln = acao in ("*", "https://evil.com") and acac == "true"
    missing = set()
    sc = resp_h.get("Set-Cookie", "")
    if "secure" not in sc.lower():
        missing.add("Secure")
    if "httponly" not in sc.lower():
        missing.add("HttpOnly")
    return {"cors_vulnerable": cors_vuln, "missing_flags": list(missing)}


def build_url_with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    qs = parse_qsl(parts.query, keep_blank_values=True)
    new_qs = [(k, v) for k, v in qs if k != param]
    new_qs.append((param, value))
    new_query = urlencode(new_qs, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


# ------------------------------------------------------------------------------
# M5: BeautifulSoup 정적 크롤러 — XSS 테스트 대상 수집
# ------------------------------------------------------------------------------

async def crawl_xss_targets(ctx: ScannerContext, url: str) -> Dict[str, List[str]]:
    """
    BeautifulSoup으로 정적 크롤링하여 XSS 테스트 대상 파라미터와 URL을 수집.

    수집 대상:
      1. <form action="..."> + <input/textarea/select name="...">
      2. <a href="?param=value"> 쿼리스트링 파라미터
      3. 현재 URL 자체의 쿼리스트링 파라미터

    반환값: { "절대URL": ["param1", "param2", ...], ... }
    """
    targets: Dict[str, List[str]] = {}
    status, _, body, final_url = await rate_limited_request(ctx, "GET", url)
    if not status or not body:
        logger.warning("[M5 Crawl] 페이지 로드 실패: %s", url)
        return targets

    soup = BeautifulSoup(body, "html.parser")
    base = urlsplit(final_url)

    def to_absolute(href: str) -> str:
        if href.startswith("http"):
            return href
        if href.startswith("/"):
            return urlunsplit((base.scheme, base.netloc, href, "", ""))
        parent_path = base.path.rsplit("/", 1)[0]
        return urlunsplit((base.scheme, base.netloc, f"{parent_path}/{href}", "", ""))

    # (1) <form> 태그 파싱
    for form in soup.find_all("form"):
        action = form.get("action") or final_url
        form_url = to_absolute(action)
        form_parsed = urlsplit(form_url)
        form_base_url = urlunsplit((form_parsed.scheme, form_parsed.netloc, form_parsed.path, "", ""))
        inline_params = [k for k, _ in parse_qsl(form_parsed.query)]
        skip_types = {"hidden", "submit", "button", "image", "reset", "file"}
        field_params = [
            tag["name"]
            for tag in form.find_all(["input", "textarea", "select"])
            if tag.get("name") and tag.get("type", "text").lower() not in skip_types
        ]
        all_params = inline_params + field_params
        if all_params:
            targets.setdefault(form_base_url, []).extend(all_params)
            logger.debug("[M5 Crawl] Form 발견: %s → params=%s", form_base_url, all_params)

    # (2) <a href="?param=value"> 쿼리스트링 파라미터 수집
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        parsed = urlsplit(href)
        if not parsed.query:
            continue
        if parsed.netloc and parsed.netloc != base.netloc:
            continue
        link_url = urlunsplit((
            parsed.scheme or base.scheme,
            parsed.netloc or base.netloc,
            parsed.path or base.path,
            "", ""
        ))
        params = [k for k, _ in parse_qsl(parsed.query)]
        if params:
            targets.setdefault(link_url, []).extend(params)
            logger.debug("[M5 Crawl] Link 발견: %s → params=%s", link_url, params)

    # (3) 현재 URL 자체의 쿼리스트링 파라미터
    if base.query:
        current_base = urlunsplit((base.scheme, base.netloc, base.path, "", ""))
        params = [k for k, _ in parse_qsl(base.query)]
        if params:
            targets.setdefault(current_base, []).extend(params)
            logger.debug("[M5 Crawl] URL 자체 파라미터: %s → params=%s", current_base, params)

    deduped = {u: list(dict.fromkeys(ps)) for u, ps in targets.items()}
    logger.info("[M5 Crawl] 수집 완료: %d개 URL, 총 %d개 파라미터",
                len(deduped), sum(len(ps) for ps in deduped.values()))
    return deduped


# ------------------------------------------------------------------------------
# M5: XSS 스캔 (크롤링 우선, 폴백은 기본 파라미터)
# ------------------------------------------------------------------------------

async def xss_scan(ctx: ScannerContext, url: str, params: List[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lock = asyncio.Lock()

    crawled = await crawl_xss_targets(ctx, url)

    if not crawled:
        logger.info("[M5] 크롤링 결과 없음 — 기본 파라미터 %s 사용", params)
        crawled = {url: params}
        source_label = "default"
    else:
        source_label = "crawled"

    async def test_param(target_url: str, p: str) -> None:
        for pl in XSS_PAYLOADS:
            test_url = build_url_with_param(target_url, p, pl)
            status, _, body, final = await rate_limited_request(ctx, "GET", test_url)
            if status and pl in body:
                async with lock:
                    findings.append({
                        "param": p,
                        "payload": pl,
                        "reflected": True,
                        "url": final,
                        "source": source_label,
                    })
                break

    tasks = [
        asyncio.create_task(test_param(t_url, p))
        for t_url, ps in crawled.items()
        for p in ps
    ]
    await asyncio.gather(*tasks)
    return findings


async def sqli_scan(ctx: ScannerContext, url: str, params: List[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    async def test_error(p: str) -> Optional[Dict[str, Any]]:
        for pl in SQLI_ERROR_PAYLOADS:
            status, _, body, _ = await rate_limited_request(ctx, "GET", build_url_with_param(url, p, pl))
            if status and (status >= 500 or re.search(r"SQL|syntax|database|mysql|oracle|postgres", body, re.I)):
                return {"type": "error-based", "param": p}
        return None

    async def test_boolean(p: str) -> Optional[Dict[str, Any]]:
        for t_pl, f_pl in SQLI_BOOLEAN_PAYLOADS:
            t_s, _, t_b, _ = await rate_limited_request(ctx, "GET", build_url_with_param(url, p, t_pl))
            f_s, _, f_b, _ = await rate_limited_request(ctx, "GET", build_url_with_param(url, p, f_pl))
            if t_s and f_s and abs(len(t_b) - len(f_b)) > SQLI_BOOLEAN_DIFF_THRESHOLD:
                return {"type": "boolean-based", "param": p}
        return None

    async def test_time(p: str) -> Optional[Dict[str, Any]]:
        if ctx.safe_mode:
            return None
        for pl in SQLI_TIME_PAYLOADS:
            start = time.monotonic()
            status, _, _, _ = await rate_limited_request(ctx, "GET", build_url_with_param(url, p, pl))
            if status:
                delay = time.monotonic() - start
                if delay > SQLI_TIME_DELAY_THRESHOLD:
                    return {"type": "time-based", "param": p, "delay": delay}
        return None

    for p in params:
        for fn in (test_error, test_boolean, test_time):
            try:
                res = await fn(p)
            except httpx.HTTPError:
                logger.exception("SQLi test error for %s", p)
                continue
            if res:
                results.append(res)
                break
    return results


async def auth_bypass_scan(
    ctx: ScannerContext,
    url: str,
    id_param: str,
    id_range: Tuple[int, int]
) -> Dict[str, Any]:
    idor_res: Optional[Dict[str, Any]] = None
    lower, upper = id_range
    if 0 <= lower <= upper <= 10000:
        for i in range(lower, upper + 1):
            status, _, body, _ = await rate_limited_request(ctx, "GET", build_url_with_param(url, id_param, str(i)))
            if status and status < 400 and "error" not in body.lower():
                idor_res = {"accessible_id": i}
                break
    else:
        logger.error("Invalid ID range %s", id_range)

    jwt_bypass = False
    try:
        await ctx.rate_limiter.acquire()
        session = await ctx.get_session()
        resp = await session.get(url, timeout=HTTP_TIMEOUT)
        set_cookie = resp.headers.get("Set-Cookie", "")
        m = re.search(r"jwt=([^;]+)", set_cookie)
        token = m.group(1) if m else ""
        if token:
            jwt_bypass = await _attempt_jwt_none(url, token, ctx)
    except httpx.HTTPError:
        logger.exception("JWT bypass error")
    return {"idor": idor_res, "jwt": {"alg_none": jwt_bypass}}


async def _attempt_jwt_none(url: str, token: str, ctx: ScannerContext) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_b, payload_b, _ = parts
    pad = lambda s: s + "=" * ((4 - len(s) % 4) % 4)
    try:
        hdr = json.loads(base64.urlsafe_b64decode(pad(header_b)))
        hdr["alg"] = "none"
        nh = base64.urlsafe_b64encode(json.dumps(hdr).encode()).decode().rstrip("=")
        pl = json.loads(base64.urlsafe_b64decode(pad(payload_b)))
        np = base64.urlsafe_b64encode(json.dumps(pl).encode()).decode().rstrip("=")
        forged = f"{nh}.{np}."
        status, _, _, _ = await rate_limited_request(ctx, "GET", url, headers={"Authorization": f"Bearer {forged}"})
        return status is not None and status < 400
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return False


async def ssrf_xxe_scan(ctx: ScannerContext, url: str, param: str) -> Dict[str, Any]:
    ssrf_detect: Optional[Dict[str, Any]] = None
    if not ctx.safe_mode:
        for tgt in INTERNAL_IP_TARGETS:
            await ctx.rate_limiter.acquire()
            status, _, _, _ = await rate_limited_request(ctx, "GET", build_url_with_param(url, param, tgt))
            if status and status < 500:
                ssrf_detect = {"responded": True, "target": tgt}
                break

    xxe_detect: Optional[Dict[str, Any]] = None
    xml_payload = ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                   '"http://127.0.0.1/">]><foo>&xxe;</foo>')
    try:
        await ctx.rate_limiter.acquire()
        session = await ctx.get_session()
        resp = await session.post(url, data=xml_payload, headers={"Content-Type": "application/xml"}, timeout=HTTP_TIMEOUT)
        if "127.0.0.1" in resp.text or resp.status_code >= 500:
            xxe_detect = {"possible": True}
    except httpx.HTTPError:
        logger.exception("XXE test error for %s", url)
    return {"ssrf": ssrf_detect, "xxe": xxe_detect}


async def check_s3_public(ctx: ScannerContext, bucket: str) -> bool:
    await ctx.rate_limiter.acquire()
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        session = await ctx.get_session()
        resp = await session.get(url, timeout=HTTP_TIMEOUT)
        return resp.status_code == 200 and "<ListBucketResult" in resp.text
    except httpx.HTTPError:
        logger.exception("S3 check error for %s", bucket)
        return False


async def check_imds_accessible(ctx: ScannerContext) -> bool:
    await ctx.rate_limiter.acquire()
    try:
        session = await ctx.get_session()
        resp = await session.get("http://169.254.169.254/latest/meta-data/", timeout=2.0)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


async def cloud_config_scan(ctx: ScannerContext, bucket_or_host: str) -> Dict[str, bool]:
    is_bucket = "." in bucket_or_host
    s3 = await check_s3_public(ctx, bucket_or_host) if is_bucket else False
    imds = False if ctx.safe_mode else await check_imds_accessible(ctx)
    return {"s3_public": s3, "imds_accessible": imds}


async def fuzzing_scan(ctx: ScannerContext, base_url: str, wordlist: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    wordlist = wordlist or COMMON_FUZZ_WORDLIST
    base = base_url.rstrip("/")
    found: List[Dict[str, Any]] = []
    lock = asyncio.Lock()

    async def probe(path: str) -> None:
        await ctx.rate_limiter.acquire()
        status, _, body, _ = await rate_limited_request(ctx, "GET", f"{base}/{path}")
        if status and (status == 200 or ("Index of /" in body and status < 400)):
            async with lock:
                found.append({"path": "/" + path, "status": status})

    tasks = [asyncio.create_task(probe(w)) for w in wordlist]
    await asyncio.gather(*tasks)
    return found


async def open_redirect_scan(ctx: ScannerContext, url: str, redirect_param: str) -> Dict[str, Any]:
    evil = "https://evil.com/"
    test_url = build_url_with_param(url, redirect_param, evil)
    status, headers, _, _ = await rate_limited_request(ctx, "GET", test_url, follow_redirects=False)
    loc = headers.get("Location")
    return {"vulnerable": bool(loc and evil in loc), "redirected_to": loc}


def classify_risk(results: Dict[str, Any]) -> str:
    high_indicators = [
        ("m1_ssl_tls", lambda r: bool(r and r.get("vulnerable"))),
        ("m2_ports", lambda r: bool(r and any(p.get("cve") for p in r))),
        ("m5_xss", lambda r: bool(r)),
        ("m6_sqli", lambda r: bool(r)),
        ("m7_auth", lambda r: bool(r and (r.get("idor") or r.get("jwt", {}).get("alg_none")))),
        ("m8_ssrf_xxe", lambda r: bool(r and (r.get("ssrf") or r.get("xxe")))),
        ("m11_open_redirect", lambda r: bool(r and r.get("vulnerable"))),
    ]
    for key, fn in high_indicators:
        if key in results and fn(results.get(key)):
            return "H"
    medium_indicators = [
        ("m3_headers", lambda r: bool(r and r.get("missing_headers"))),
        ("m4_cors_cookie", lambda r: bool(r and (r.get("cors_vulnerable") or r.get("missing_flags")))),
        ("m9_cloud", lambda r: bool(r and (r.get("s3_public") or r.get("imds_accessible")))),
        ("m10_fuzz", lambda r: bool(r)),
    ]
    for key, fn in medium_indicators:
        if key in results and fn(results.get(key)):
            return "M"
    return "L"


async def run_scan(
    target: str,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    safe_mode: bool = DEFAULT_SAFE_MODE,
    verify_ssl: bool = True,
    port_range: Tuple[int, int] = (1, 1024),
    xss_params: Optional[List[str]] = None,
    sqli_params: Optional[List[str]] = None,
    id_param: str = "id",
    id_range: Tuple[int, int] = (1, 100),
    ssrf_param: str = "url",
    redirect_param: str = "redirect",
    port_workers: int = DEFAULT_PORT_WORKERS,
) -> Dict[str, Any]:
    ctx = ScannerContext(target, rate_limit, safe_mode, verify_ssl)
    host, port = extract_host_port(target)
    xss_params = xss_params or ["q", "search"]
    sqli_params = sqli_params or ["id"]
    scanners: List[Tuple[str, Callable[..., Any], Tuple[Any, ...]]] = [
        ("m1_ssl_tls", ssl_tls_scan, (ctx, host, port)),
        ("m2_ports", port_scan_banner, (ctx, host, port_range, port_workers)),
        ("m3_headers", security_headers_check, (ctx, target,)),
        ("m4_cors_cookie", cors_cookie_check, (ctx, target,)),
        ("m5_xss", xss_scan, (ctx, target, xss_params)),
        ("m6_sqli", sqli_scan, (ctx, target, sqli_params)),
        ("m7_auth", auth_bypass_scan, (ctx, target, id_param, id_range)),
        ("m8_ssrf_xxe", ssrf_xxe_scan, (ctx, target, ssrf_param)),
        ("m9_cloud", cloud_config_scan, (ctx, host,)),
        ("m10_fuzz", fuzzing_scan, (ctx, target,)),
        ("m11_open_redirect", open_redirect_scan, (ctx, target, redirect_param)),
    ]
    tasks = {name: asyncio.create_task(func(*args)) for name, func, args in scanners}
    results: Dict[str, Any] = {}
    done = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for (name, _func, _args), res in zip(scanners, done):
        if isinstance(res, Exception):
            logger.error("Scanner %s failed: %s", name, res)
            results[name] = {"error": str(res)}
        else:
            results[name] = res
    risk = classify_risk(results)
    report = {
        "target": target,
        "safe_mode": safe_mode,
        "verify_ssl": verify_ssl,
        "rate_limit": rate_limit,
        "risk": risk,
        "results": results,
    }
    await ctx.close()
    return report


# ------------------------------------------------------------------------------
# o4-mini 최종 종합 분석
# ------------------------------------------------------------------------------

def build_scan_summary_for_ai(report: dict) -> str:
    """AI에게 넘길 스캔 결과 요약 텍스트 생성 (검출된 항목만 포함)."""
    res = report.get("results", {})
    lines = [
        f"대상 URL: {report.get('target')}",
        f"종합 위험도: {report.get('risk')}",
        "",
        "[ 검출된 취약점 목록 ]",
    ]

    findings = []

    if res.get("m5_xss"):
        for item in res["m5_xss"]:
            findings.append(f"- M5 XSS: 파라미터 '{item['param']}' 반사형 XSS, payload={item['payload']}")

    if res.get("m6_sqli"):
        for item in res["m6_sqli"]:
            delay = f", 응답지연={item['delay']:.2f}s" if "delay" in item else ""
            findings.append(f"- M6 SQLi: 파라미터 '{item['param']}' {item.get('type', '')} 취약점{delay}")

    if res.get("m7_auth"):
        auth = res["m7_auth"]
        if auth.get("idor"):
            findings.append(f"- M7 IDOR: ID={auth['idor'].get('accessible_id')} 무단 접근 가능")
        if auth.get("jwt", {}).get("alg_none"):
            findings.append("- M7 JWT: alg=none 서명 우회 성공")

    if res.get("m8_ssrf_xxe"):
        s = res["m8_ssrf_xxe"]
        if s.get("ssrf"):
            findings.append(f"- M8 SSRF: 내부망 {s['ssrf'].get('target')} 요청 성공")
        if s.get("xxe"):
            findings.append("- M8 XXE: XML 외부 엔티티 삽입 가능")

    if res.get("m10_fuzz"):
        paths = [i["path"] for i in res["m10_fuzz"]]
        findings.append(f"- M10 퍼징: 민감 경로 노출 {paths}")

    if res.get("m1_ssl_tls", {}).get("vulnerable"):
        findings.append(f"- M1 SSL/TLS: 취약한 프로토콜/암호화 사용 ({res['m1_ssl_tls'].get('protocol')})")

    if res.get("m2_ports"):
        vuln_ports = [p for p in res["m2_ports"] if p.get("cve")]
        if vuln_ports:
            findings.append(f"- M2 포트스캔: CVE 취약점 포트 발견 {[p['port'] for p in vuln_ports]}")

    if res.get("m3_headers", {}).get("missing_headers"):
        findings.append(f"- M3 보안 헤더 누락: {res['m3_headers']['missing_headers']}")

    if res.get("m4_cors_cookie", {}).get("missing_flags"):
        findings.append(f"- M4 쿠키 플래그 누락: {res['m4_cors_cookie']['missing_flags']}")

    if res.get("m4_cors_cookie", {}).get("cors_vulnerable"):
        findings.append("- M4 CORS: 외부 Origin 허용 + credentials=true")

    if res.get("m9_cloud", {}).get("s3_public"):
        findings.append("- M9 클라우드: AWS S3 버킷 공개 노출")
    if res.get("m9_cloud", {}).get("imds_accessible"):
        findings.append("- M9 클라우드: IMDS 메타데이터 접근 가능")

    if res.get("m11_open_redirect", {}).get("vulnerable"):
        findings.append(f"- M11 Open Redirect: {res['m11_open_redirect'].get('redirected_to')}")

    if not findings:
        findings.append("- 검출된 취약점 없음")

    lines.extend(findings)
    return "\n".join(lines)


def ai_final_summary(report: dict, openai_api_key: str) -> str:
    """
    gpt-4o-mini에게 스캔 결과를 넘겨 최종 종합 권고문을 생성.
    API 실패 시 기존 고정 문자열로 폴백.
    """
    def _fallback() -> str:
        risk = report.get("risk", "L")
        if risk == "H":
            return "이 서버는 매우 위험한 상태(High)입니다. 검출된 취약점을 즉시 조치하세요."
        elif risk == "M":
            return "이 서버는 중간 위험 상태(Medium)입니다. 보안 설정을 강화하세요."
        return "이 서버는 전반적으로 양호한 상태(Low)입니다."

    summary = build_scan_summary_for_ai(report)
    system_prompt = (
        "당신은 웹 보안 전문가입니다. "
        "아래 취약점 스캔 결과를 바탕으로 최종 종합 상태 권고문을 한국어로 작성하세요. "
        "검출된 취약점들의 심각도와 실제 위협을 구체적으로 언급하고, "
        "우선순위별 조치 방법을 3~5문장으로 간결하게 작성하세요. "
        "없는 취약점은 절대 언급하지 마세요."
    )
    
    # 👇👇 모델명과 파라미터가 수정된 부분입니다 👇👇
    payload = {
        "model": "gpt-4o-mini",  
        "max_tokens": 512,       
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": summary},
        ],
    }

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                "https://api.openai.com/v1/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {openai_api_key}"},
            )
        if resp.status_code != 200:
            logger.error(
                "OpenAI API 오류 — HTTP %d: %s",
                resp.status_code, resp.text[:300]
            )
            return _fallback()

        data = resp.json()
        content = data["choices"][0]["message"]["content"].strip()
        if not content:
            logger.warning("AI 응답 내용이 비어 있음 — 기본 메시지로 대체")
            return _fallback()
        return content

    except (httpx.HTTPError, KeyError, IndexError, json.JSONDecodeError) as e:
        logger.error("API 호출 실패 (%s: %s) — 기본 메시지로 대체", type(e).__name__, e)
        return _fallback()

# ------------------------------------------------------------------------------
# 리포트 생성
# ------------------------------------------------------------------------------

def generate_human_report(report: dict, openai_api_key: Optional[str] = None) -> str:
    lines = []
    lines.append("=" * 50)
    lines.append("📊 취약점 진단 결과 요약 리포트")
    lines.append("=" * 50)
    lines.append(f"[*] 대상 URL: {report.get('target')}")
    lines.append(f"[*] 종합 위험도: {report.get('risk')}\n")

    res = report.get("results", {})

    # M1
    lines.append("M1. SSL/TLS 취약점")
    if res.get("m1_ssl_tls") and res["m1_ssl_tls"].get("vulnerable"):
        lines.append("- 위험도 : H\n- 이유 : 안전하지 않은 SSL/TLS 버전 또는 취약한 암호화가 사용됨.")
    else:
        lines.append("- 상태 : 양호 (취약점 없음)")
    lines.append("")

    # M2
    lines.append("M2. 포트 스캔 및 취약점(CVE) 노출")
    open_ports = res.get("m2_ports", []) # 스캐너가 찾아낸 열린 포트 전체
    vuln_ports = [p for p in open_ports if p.get("cve")] # 그 중 CVE가 있는 포트

    if vuln_ports:
        lines.append("- 위험도 : H\n- 이유 : 열린 포트에서 알려진 취약점(CVE)이 발견됨.")
        for vp in vuln_ports:
            lines.append(f"  * Port {vp['port']}: {', '.join(vp['cve'][:3])} 등")
    elif open_ports:
        # 💡 CVE는 없지만 열린 포트는 찾은 경우!
        lines.append("- 위험도 : L")
        ports_str = ", ".join(str(p['port']) for p in open_ports)
        lines.append(f"- 이유 : 취약점은 없으나 외부로 개방된 포트({ports_str}번)가 발견됨. 불필요한 포트인지 점검 필요.")
    else:
        lines.append("- 상태 : 양호 (열린 포트 없음)")
    lines.append("")

    # M3
    lines.append("M3. 보안 헤더 누락")
    if res.get("m3_headers") and res["m3_headers"].get("missing_headers"):
        lines.append("- 위험도 : M")
        lines.append(f"- 이유 : 필수 방어 헤더({', '.join(res['m3_headers']['missing_headers'])})가 누락됨.")
    else:
        lines.append("- 상태 : 양호 (모두 적용됨)")
    lines.append("")

    # M4
    lines.append("M4. 쿠키 보안 설정 누락")
    if res.get("m4_cors_cookie") and res["m4_cors_cookie"].get("missing_flags"):
        lines.append("- 위험도 : M")
        lines.append(f"- 이유 : 쿠키에 보안 플래그({', '.join(res['m4_cors_cookie']['missing_flags'])})가 설정되지 않음.")
    else:
        lines.append("- 상태 : 양호 (안전한 설정)")
    lines.append("")

    # M5
    lines.append("M5. XSS (크로스 사이트 스크립팅)")
    if res.get("m5_xss"):
        lines.append("- 위험도 : H")
        for item in res["m5_xss"]:
            src = item.get("source", "unknown")
            lines.append(f"- 이유 : 파라미터({item['param']})에 XSS 취약점 확인 [{src}] / payload: {item['payload']}")
    else:
        lines.append("- 상태 : 양호 (취약점 없음)")
    lines.append("")

    # M6
    lines.append("M6. SQL 인젝션 (SQLi)")
    if res.get("m6_sqli"):
        lines.append("- 위험도 : H")
        delay = res['m6_sqli'][0].get('delay', 0)
        if delay:
            lines.append(f"- 이유 : 파라미터({res['m6_sqli'][0]['param']})에 Time-based 페이로드 주입 시 {delay:.2f}초 지연 확인됨.")
        else:
            lines.append(f"- 이유 : 파라미터({res['m6_sqli'][0]['param']})에서 SQLi 에러/논리 취약점 발견됨.")
    else:
        lines.append("- 상태 : 양호 (취약점 없음)")
    lines.append("")

    # M7
    lines.append("M7. 인증 우회 (IDOR & JWT)")
    if res.get("m7_auth") and (res["m7_auth"].get("idor") or res["m7_auth"].get("jwt", {}).get("alg_none")):
        lines.append("- 위험도 : H")
        reasons = []
        if res["m7_auth"].get("idor"):
            reasons.append(f"인가되지 않은 ID({res['m7_auth']['idor'].get('accessible_id')}) 객체 접근 가능")
        if res["m7_auth"].get("jwt", {}).get("alg_none"):
            reasons.append("JWT alg:none 서명 우회 가능")
        lines.append(f"- 이유 : {', '.join(reasons)}")
    else:
        lines.append("- 상태 : 양호 (취약점 없음)")
    lines.append("")

    # M8
    lines.append("M8. 서버 측 요청 위조 (SSRF & XXE)")
    if res.get("m8_ssrf_xxe") and (res["m8_ssrf_xxe"].get("ssrf") or res["m8_ssrf_xxe"].get("xxe")):
        lines.append("- 위험도 : H")
        reasons = []
        if res["m8_ssrf_xxe"].get("ssrf"):
            reasons.append(f"내부망 IP({res['m8_ssrf_xxe']['ssrf'].get('target')}) 강제 요청 성공")
        if res["m8_ssrf_xxe"].get("xxe"):
            reasons.append("XXE 외부 엔티티 주입 성공")
        lines.append(f"- 이유 : {', '.join(reasons)}")
    else:
        lines.append("- 상태 : 양호 (취약점 없음)")
    lines.append("")

    # M9
    lines.append("M9. 클라우드 설정 검사")
    if res.get("m9_cloud") and (res["m9_cloud"].get("s3_public") or res["m9_cloud"].get("imds_accessible")):
        lines.append("- 위험도 : H")
        lines.append("- 이유 : AWS S3 버킷 공개 노출 또는 IMDS 메타데이터 접근 가능함.")
    else:
        lines.append("- 상태 : 양호 (발견 안 됨)")
    lines.append("")

    # M10
    lines.append("M10. 퍼징 (숨겨진 파일 탐색)")
    if res.get("m10_fuzz"):
        lines.append("- 위험도 : H")
        paths = [item['path'] for item in res['m10_fuzz']]
        lines.append(f"- 이유 : 민감 파일 및 디렉터리({', '.join(paths)})에 외부 접근이 허용됨.")
    else:
        lines.append("- 상태 : 양호 (발견 안 됨)")
    lines.append("")

    # M11
    lines.append("M11. Open Redirect")
    if res.get("m11_open_redirect") and res["m11_open_redirect"].get("vulnerable"):
        lines.append("- 위험도 : H")
        lines.append("- 이유 : 외부 도메인(악성 사이트 등)으로의 강제 리다이렉션이 가능함.")
    else:
        lines.append("- 상태 : 양호 (취약점 없음)")
    lines.append("")

    # 최종 종합 상태
    lines.append("=" * 50)
    lines.append("[최종 종합 상태]")
    if openai_api_key:
        print("🤖 o4-mini 분석 중...", flush=True)
        final_summary = ai_final_summary(report, openai_api_key)
    else:
        risk = report.get("risk", "L")
        if risk == "H":
            final_summary = "이 서버는 매우 위험한 상태(High)입니다. DB 쿼리 및 내부망 접근 통제, 민감 파일 노출 차단이 시급합니다."
        elif risk == "M":
            final_summary = "이 서버는 중간 위험 상태(Medium)입니다. 보안 헤더 및 쿠키 설정을 강화해야 합니다."
        else:
            final_summary = "이 서버는 전반적으로 양호한 상태(Low)입니다."
    lines.append(final_summary)
    lines.append("=" * 50 + "\n")

    return "\n".join(lines)


class FriendlyArgParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        sys.stderr.write(f"Error: {message}\nUse -h for help.\n")
        sys.exit(2)


def main() -> None:
    parser = FriendlyArgParser(description="Automated Security Vulnerability Scanner")
    parser.add_argument("target", nargs='?', help="URL or IP to scan")
    parser.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT, help="Requests per second")
    parser.add_argument("--unsafe", action="store_true", help="Allow destructive payloads")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--ports", type=str, default="1-1024", help="Port range, e.g. 1-1024")
    parser.add_argument("--output", type=str, default="report.json", help="Output file")
    parser.add_argument("--openai-key", type=str, default=None,
                        help="OpenAI API key for o4-mini final summary (또는 환경변수 OPENAI_API_KEY 사용)")
    args = parser.parse_args()
    if not args.target:
        parser.error("Target is required.")
    target = args.target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        if not urlparse(target).netloc:
            parser.error("Invalid URL provided.")
    else:
        if is_valid_ip(target) or re.match(r"^[a-zA-Z0-9.-]+$", target):
            target = f"http://{target}"
        else:
            parser.error("Invalid host provided.")
    try:
        if "-" in args.ports:
            pmin, pmax = map(int, args.ports.split("-", 1))
        else:
            pmin = pmax = int(args.ports)
    except ValueError:
        parser.error("Invalid port range format.")

    report = asyncio.run(run_scan(
        target,
        rate_limit=args.rate_limit,
        safe_mode=not args.unsafe,
        verify_ssl=not args.insecure,
        port_range=(pmin, pmax),
    ))

    try:
        # 1. JSON 파일 저장
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info("Report(JSON) written to %s", args.output)

        # 2. 텍스트 리포트 생성 (o4-mini 키 있으면 AI 분석 포함)
        openai_key = args.openai_key or os.environ.get("OPENAI_API_KEY")
        report_text = generate_human_report(report, openai_api_key=openai_key)
        print(report_text)

        # 3. 텍스트 리포트 .txt 파일로 저장
        txt_filename = args.output.replace(".json", ".txt")
        if not txt_filename.endswith(".txt"):
            txt_filename += ".txt"
        with open(txt_filename, "w", encoding="utf-8") as f:
            f.write(report_text)
        logger.info("Report(TXT) written to %s", txt_filename)

    except OSError:
        logger.exception("Error writing output files")


if __name__ == "__main__":
    main()