# src/crawler.py
from __future__ import annotations

import logging
import socket
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlparse, urljoin

import requests

from .parser import parse_html
from .rules_engine import rules_score
from .validator import validate_url
from .config import USER_AGENT, REQUEST_TIMEOUT, RULES_HIGH, RULES_LOW
from .screenshots import screenshot_base64

logger = logging.getLogger("bima.crawler")

MAX_BODY_BYTES = 200_000  # bytes to read to avoid OOM

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "bank", "confirm", "password"]


@dataclass
class CrawlResult:
    url: str
    status: str                   # "ok" | "error" | "blocked"
    status_code: Optional[int]
    content_length: int
    reachable: bool
    parsed: Optional[dict]
    rules_score: float
    rules_label: str              # "phishing" | "legit" | "uncertain"
    error: Optional[str] = None
    screenshot: Optional[str] = None  # data URL (base64) for visual evidence

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "reachable": self.reachable,
            "rules_score": self.rules_score,
            "rules_label": self.rules_label,
            "error": self.error,
            "parsed": self.parsed,
            "screenshot": self.screenshot,
        }


# Simple SSRF protection: ensure hostname resolves to public IPs
def _is_public_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
        addrs = {info[4][0] for info in infos if info and info[4]}
        for addr in addrs:
            ip = ipaddress.ip_address(addr)
            # reject private/reserved addresses
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                logger.warning("Reject private/reserved IP %s for host %s", addr, hostname)
                return False
        return True
    except Exception as e:
        # DNS resolution failed — be conservative and deny
        logger.debug("Hostname resolution failed for %s: %s", hostname, e)
        return False


def _safe_fetch(url: str, timeout: int = REQUEST_TIMEOUT, max_bytes: int = MAX_BODY_BYTES) -> Tuple[Optional[int], str, str]:
    headers = {"User-Agent": USER_AGENT}
    try:
        with requests.get(url, headers=headers, timeout=timeout, stream=True, allow_redirects=True) as r:
            status = r.status_code
            content_type = r.headers.get("content-type", "")
            # capture final url and redirect hops for additional features
            final_url = getattr(r, "url", url)
            redirect_count = len(getattr(r, "history", []) or [])
            if content_type and "text" in content_type.lower():
                total = 0
                chunks: List[bytes] = []
                for chunk in r.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        break
                    chunks.append(chunk)
                body = b"".join(chunks)
                try:
                    text = body.decode("utf-8", errors="replace")
                except Exception:
                    text = body.decode("latin1", errors="replace")
                return status, content_type, text, final_url, redirect_count
            else:
                # binary or non-textual content
                return status, content_type, "", final_url, redirect_count
    except requests.RequestException as e:
        logger.warning("Fetch failed for %s: %s", url, e)
        return None, "", "", url, 0
    except Exception as e:
        logger.exception("Unexpected fetch error for %s: %s", url, e)
        return None, "", "", url, 0


def _count_external_links(anchors: List[dict], base_hostname: str) -> int:
    cnt = 0
    for a in anchors:
        href = (a.get("href") or "").strip()
        if not href:
            continue
        # normalize relative -> absolute
        if href.startswith("//"):
            href = "http:" + href
        if not href.startswith("http"):
            # relative link - treat as internal
            continue
        try:
            host = urlparse(href).hostname or ""
        except Exception:
            host = ""
        if host and host.lower() != base_hostname.lower():
            cnt += 1
    return cnt


def _has_password_input(text: str) -> bool:
    if not text:
        return False
    # crude but effective: look for input type=password or word 'password' in attributes/snippets
    low = text.lower()
    if 'type="password"' in low or "type=password" in low:
        return True
    # sometimes form fields labeled password but not literal type attr (less common)
    if "password" in low and ("input" in low or "form" in low):
        return True
    return False


def _count_suspicious_words(text: str) -> int:
    if not text:
        return 0
    low = text.lower()
    return sum(1 for w in SUSPICIOUS_WORDS if w in low)


def _safe_len(x) -> int:
    # Accept ints, numeric strings, and sequences (lists/tuples/sets)
    if x is None:
        return 0
    if isinstance(x, (list, tuple, set)):
        try:
            return len(x)
        except Exception:
            return 0
    try:
        return int(x)
    except Exception:
        return 0


def crawl(url: str, capture_screenshot: bool = False) -> CrawlResult:

    url = (url or "").strip()
    if not validate_url(url):
        return CrawlResult(
            url=url,
            status="error",
            status_code=None,
            content_length=0,
            reachable=False,
            parsed=None,
            rules_score=0.0,
            rules_label="uncertain",
            error="Invalid URL"
        )

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    if not _is_public_hostname(hostname):
        return CrawlResult(
            url=url,
            status="blocked",
            status_code=None,
            content_length=0,
            reachable=False,
            parsed=None,
            rules_score=0.0,
            rules_label="uncertain",
            error="Blocked: hostname resolves to non-public IP"
        )

    # fetch page (text)
    status_code, content_type, text, final_url, redirect_count = _safe_fetch(url)
    if status_code is None:
        # fetch failed; still return a CrawlResult marking unreachable (ML may fallback)
        return CrawlResult(
            url=url,
            status="error",
            status_code=None,
            content_length=0,
            reachable=False,
            parsed=None,
            rules_score=0.0,
            rules_label="uncertain",
            error="Fetch failed"
        )

    content_len = len(text or "")

    # parse using centralized parser (returns dict with anchors/forms/scripts/body_snippet/title/meta)
    parsed_html = parse_html(text, url) if text else None

    # Build page_features (numeric, compact) from parsed_html and URL
    page_features: Dict[str, Any] = {}
    try:
        anchors = parsed_html.get("anchors", []) if parsed_html else []
        forms = parsed_html.get("forms", []) if parsed_html else []
        scripts = parsed_html.get("scripts", []) if parsed_html else []
        title = (parsed_html.get("title") or "") if parsed_html else ""
        body_snippet = (parsed_html.get("body_snippet") or "") if parsed_html else ""

        num_anchors = _safe_len(anchors and len(anchors))
        num_forms = _safe_len(forms and len(forms))
        num_scripts = _safe_len(scripts and len(scripts))
        num_external_links = _count_external_links(anchors, hostname)
        # forms_with_password: count forms that include password inputs if parser provides input details
        forms_with_password = 0
        try:
            for f in (forms or []):
                # parser may provide list of inputs per form
                inputs = f.get("inputs") if isinstance(f, dict) else None
                if inputs and any((getattr(inp, "get", None) and inp.get("type", "") == "password") or (isinstance(inp, dict) and inp.get("type") == "password") for inp in inputs):
                    forms_with_password += 1
        except Exception:
            forms_with_password = 0

        # boolean flag if any password field found in full text
        has_password_input = int(_has_password_input(text or "") or forms_with_password > 0)
        suspicious_keywords = _count_suspicious_words((body_snippet or "") + " " + (title or ""))
        title_len = len(title or "")
        text_ratio = 0.0
        if content_len:
            # body_snippet is truncated in parser; approximate text ratio using body_snippet vs content_len
            text_ratio = min(1.0, float(len(body_snippet) / max(1, content_len)))

        # final_url and redirect_count obtained from _safe_fetch
        final_url = final_url if 'final_url' in locals() else url
        redirect_count = redirect_count if 'redirect_count' in locals() else 0

        external_link_ratio = float(num_external_links) / max(1.0, float(num_anchors)) if num_anchors else 0.0

        page_features = {
            "body_len": content_len,
            "title_len": title_len,
            "num_anchors": num_anchors,
            "num_forms": num_forms,
            "num_scripts": num_scripts,
            "num_external_links": num_external_links,
            "has_password_input": has_password_input,
            "suspicious_keyword_count": suspicious_keywords,
            "text_ratio": round(text_ratio, 4),
            "forms_with_password": forms_with_password,
            "external_link_ratio": round(external_link_ratio, 4),
            "redirect_count": int(redirect_count),
            "final_url": final_url,
        }
    except Exception as e:
        logger.exception("Failed to compute page_features for %s: %s", url, e)
        page_features = {}

    # Compose a "rich" parsed object combining parser output + page_features for downstream use
    rich_parsed = {
        "parsed_html": parsed_html,
        "page_features": page_features,
    }

    # compute rules score using parsed content (rules_engine expects parsed dict with anchors/forms)
    try:
        # rules_score now returns (score, reasons)
        rscore, rreasons = rules_score(url, parsed_html or {})
        rscore = float(rscore)
    except Exception as e:
        logger.exception("rules_score computation failed for %s: %s", url, e)
        rscore = 0.0
        rreasons = []

    # map rules_score to quick label
    if rscore >= RULES_HIGH:
        rlabel = "phishing"
    elif rscore <= RULES_LOW:
        rlabel = "legit"
    else:
        rlabel = "uncertain"

    # attach rules_reasons into parsed wrapper for downstream use
    try:
        rich_parsed["rules_reasons"] = rreasons
    except Exception:
        pass

    # attempt to capture screenshot if requested (best-effort)
    screenshot_data = None
    if capture_screenshot:
        try:
            shot_target = page_features.get("final_url") if isinstance(page_features, dict) else url
            if not shot_target:
                shot_target = url
            screenshot_data = screenshot_base64(shot_target)
        except Exception as e:
            logger.warning("Screenshot capture failed for %s: %s", url, e)

    return CrawlResult(
        url=url,
        status="ok",
        status_code=status_code,
        content_length=content_len,
        reachable=True,
        parsed=rich_parsed,
        rules_score=round(rscore, 4),
        rules_label=rlabel,
        error=None,
        screenshot=screenshot_data
    )
