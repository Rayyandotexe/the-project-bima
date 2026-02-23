from typing import List, Dict, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re

SENSITIVE_RE = re.compile(r"(password|pass|pwd|pin|otp|card|cvv|cvc|ssn|account|login)", re.I)


def _abs(base: str, href: str) -> str:
    try:
        return urljoin(base or "", href or "")
    except Exception:
        return href or ""


def parse_html(html: str, base_url: str) -> Dict[str, Any]:
    """Parse HTML and return a rich dict used by rules & feature extraction.

    Returned keys (required):
      - title: str
      - meta: dict
      - anchors: list of {href, text}
      - anchor_stats: {num_anchors, num_hash_anchors, percent_hash, num_external}
      - forms: list of {action, method, inputs: [{name,type,placeholder}], sensitive: bool}
      - num_scripts, scripts_src, scripts_inline
      - images
      - body_snippet
      - page_features: compact summary (see spec)
    """
    soup = BeautifulSoup(html or "", "lxml")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    # meta
    metas: Dict[str, str] = {}
    for m in soup.find_all("meta"):
        key = (m.get("property") or m.get("name") or "")
        if key:
            content = m.get("content")
            if content:
                metas[str(key).strip()] = content

    # anchors
    anchors: List[Dict[str, str]] = []
    for a in soup.find_all("a"):
        href = a.get("href") or ""
        text = a.get_text(separator=" ", strip=True) or ""
        abs_href = _abs(base_url, href)
        anchors.append({"href": abs_href, "text": text})

    # anchor stats
    num_anchors = len(anchors)
    num_hash = 0
    num_external = 0
    base_host = (urlparse(base_url).hostname or "").lower()
    for a in anchors:
        h = (a.get("href") or "").strip()
        if not h or h in ("#", "", "javascript:void(0)"):
            num_hash += 1
            continue
        try:
            ah = urlparse(h).hostname or ""
        except Exception:
            ah = ""
        if ah and ah.lower() != base_host:
            num_external += 1

    percent_hash = float(num_hash) / max(1.0, float(num_anchors)) if num_anchors else 0.0

    # forms
    forms: List[Dict[str, Any]] = []
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "").lower() or "get"
        abs_action = _abs(base_url, action)
        inputs: List[Dict[str, str]] = []
        sensitive = False
        for inp in f.find_all(["input", "textarea", "select"]):
            try:
                name = (inp.get("name") or inp.get("id") or "")
                itype = (inp.get("type") or "text").lower()
                placeholder = inp.get("placeholder") or ""
                inputs.append({"name": name, "type": itype, "placeholder": placeholder})
                if itype == "password" or SENSITIVE_RE.search(name or "") or SENSITIVE_RE.search(placeholder or ""):
                    sensitive = True
            except Exception:
                continue
        forms.append({"action": abs_action, "method": method, "inputs": inputs, "sensitive": sensitive})

    # scripts
    scripts_src: List[str] = []
    scripts_inline: List[str] = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            scripts_src.append(_abs(base_url, src))
        else:
            txt = (s.string or "")
            if txt and txt.strip():
                scripts_inline.append(txt.strip()[:2000])

    # images
    images: List[str] = []
    for im in soup.find_all("img"):
        src = im.get("src") or im.get("data-src") or ""
        if src:
            images.append(_abs(base_url, src))

    body = soup.get_text(separator=" ", strip=True)[:20000]

    # page features (compact)
    body_len = len(body)
    text_ratio = 0.0
    try:
        text_ratio = float(len(body) / max(1, len(html or ""))) if html else 0.0
    except Exception:
        text_ratio = 0.0

    num_forms = len(forms)
    num_scripts = len(scripts_src) + len(scripts_inline)
    has_password_input = 1 if any(f.get("sensitive") for f in forms) else 0
    forms_with_password = sum(1 for f in forms if f.get("sensitive"))

    page_features = {
        "body_len": body_len,
        "text_ratio": round(text_ratio, 6),
        "num_anchors": num_anchors,
        "num_external_links": num_external,
        "num_forms": num_forms,
        "num_scripts": num_scripts,
        "has_password_input": int(has_password_input),
        "forms_with_password": int(forms_with_password),
        "percent_hash_anchors": round(percent_hash, 4),
        "title_len": len(title or ""),
        "final_url": base_url,
    }

    return {
        "title": title,
        "meta": metas,
        "anchors": anchors,
        "anchor_stats": {"num_anchors": num_anchors, "num_hash_anchors": num_hash, "percent_hash": round(percent_hash, 4), "num_external": num_external},
        "forms": forms,
        "num_scripts": num_scripts,
        "scripts_src": scripts_src,
        "scripts_inline": scripts_inline,
        "images": images,
        "body_snippet": body,
        "page_features": page_features,
    }


def extract_page_features(html: str, url: str) -> Dict[str, Any]:
    parsed = parse_html(html, url)
    return parsed.get("page_features") or {}
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re


def parse_html(html: str, url: str) -> dict:
    """Parse HTML and return structured info useful for feature extraction.

    Returned dict contains:
      - title, meta (dict)
      - anchors: list of {href, text}
      - forms: list of {action, method, inputs: [{name,type,placeholder}]}
      - scripts_src: list of script src URLs
      - scripts_inline: list of inline script snippets (trimmed)
      - images: list of src
      - body_snippet: text snippet
    """
    soup = BeautifulSoup(html or "", "lxml")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    metas = {}
    for m in soup.find_all("meta"):
        key = (m.get("name") or m.get("property") or "")
        if not key:
            continue
        key = str(key).strip()
        if not key:
            continue
        content = m.get("content")
        if content:
            metas[key] = content

    anchors = []
    for a in soup.find_all("a"):
        href = a.get("href") or ""
        text = a.get_text(strip=True) or ""
        anchors.append({"href": href, "text": text})

    forms = []
    for f in soup.find_all("form"):
        inputs = []
        for inp in f.find_all(["input", "textarea", "select"]):
            try:
                iname = inp.get("name") or inp.get("id") or ""
                itype = (inp.get("type") or "text").lower()
                ipl = inp.get("placeholder") or ""
                inputs.append({"name": iname, "type": itype, "placeholder": ipl})
            except Exception:
                continue
        forms.append({"action": (f.get("action") or ""), "method": (f.get("method") or ""), "inputs": inputs})

    scripts_src = []
    scripts_inline = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            scripts_src.append(src)
        else:
            txt = (s.string or "")
            if txt and txt.strip():
                # keep only short snippets to avoid huge payloads
                scripts_inline.append(txt.strip()[:2000])

    images = []
    for im in soup.find_all("img"):
        src = im.get("src") or im.get("data-src") or ""
        if src:
            images.append(src)

    body = soup.get_text(separator=" ", strip=True)[:2000]

    return {
        "title": title,
        "meta": metas,
        "anchors": anchors,
        "forms": forms,
        "scripts_src": scripts_src,
        "scripts_inline": scripts_inline,
        "images": images,
        "body_snippet": body,
    }


def extract_page_features(html: str, url: str) -> dict:
    """Return extracted numeric/boolean page features from HTML and URL.

    Designed to be robust and return defaults for missing values.
    """
    parsed = parse_html(html, url)
    host = (urlparse(url).hostname or "")

    anchors = parsed.get("anchors") or []
    forms = parsed.get("forms") or []
    scripts_src = parsed.get("scripts_src") or []
    scripts_inline = parsed.get("scripts_inline") or []
    images = parsed.get("images") or []
    title = parsed.get("title") or ""
    body = parsed.get("body_snippet") or ""

    num_anchors = len(anchors)
    num_forms = len(forms)
    num_scripts = len(scripts_src) + len(scripts_inline)
    num_images = len(images)

    # external anchors count
    ext_anchors = 0
    anchor_mismatch = 0
    suspicious_keywords = ("login", "signin", "verify", "secure", "account", "update", "confirm", "bank", "password", "otp")
    for a in anchors:
        href = (a.get("href") or "").strip()
        text = (a.get("text") or "").strip()
        if not href:
            continue
        if href.startswith("//"):
            href = "http:" + href
        if not href.startswith("http"):
            # relative => internal
            continue
        try:
            ahost = urlparse(href).hostname or ""
        except Exception:
            ahost = ""
        if ahost and ahost.lower() != host.lower():
            ext_anchors += 1
        # anchor mismatch heuristic: anchor text contains suspicious keyword but href doesn't
        lt = text.lower()
        for kw in suspicious_keywords:
            if kw in lt and kw not in (href or "").lower():
                anchor_mismatch += 1
                break

    # form sensitive fields
    forms_with_password = 0
    form_sensitive_count = 0
    total_inputs = 0
    sensitive_tokens = ("card", "ccv", "cvv", "ssn", "otp", "password", "pin", "cardnumber")
    for f in forms:
        inputs = f.get("inputs") or []
        has_pw = any((inp.get("type") or "").lower() == "password" for inp in inputs)
        if has_pw:
            forms_with_password += 1
        cnt = sum(1 for inp in inputs if any(tok in (inp.get("name") or "").lower() for tok in sensitive_tokens) or any(tok in (inp.get("placeholder") or "").lower() for tok in sensitive_tokens))
        form_sensitive_count += cnt
        total_inputs += len(inputs)

    # inline eval detection
    inline_code = "\n".join(scripts_inline)
    has_inline_eval = 1 if ("eval(" in inline_code or "setInterval(" in inline_code or "setTimeout(" in inline_code) else 0

    title_len = len(title or "")
    meta = parsed.get("meta") or {}
    meta_desc = (meta.get("description") or meta.get("og:description") or "")
    meta_description_contains_login = 1 if any(k in (meta_desc or "").lower() for k in suspicious_keywords) else 0

    # images host mismatch
    images_host_mismatch = 0
    for im in images:
        try:
            ih = urlparse(im).hostname or ""
        except Exception:
            ih = ""
        if ih and ih.lower() != host.lower():
            images_host_mismatch += 1

    # aggregate suspicious keyword count from url+path+body
    path = urlparse(url).path or ""
    query = urlparse(url).query or ""
    combined = " ".join([url, path, query, body]).lower()
    suspicious_keyword_count = sum(1 for k in suspicious_keywords if k in combined)

    # anchor to body ratio
    anchor_to_body_ratio = float(num_anchors) / max(1.0, float(len(body) if body else 1)) if body else float(num_anchors)

    return {
        "body_len": len(body),
        "num_anchors": num_anchors,
        "num_anchors_external": ext_anchors,
        "anchor_mismatch_count": anchor_mismatch,
        "num_forms": num_forms,
        "form_contains_password": 1 if forms_with_password else 0,
        "form_sensitive_count": form_sensitive_count,
        "num_inputs": total_inputs,
        "num_scripts": num_scripts,
        "has_inline_eval": has_inline_eval,
        "title_len": title_len,
        "meta_description_contains_login": meta_description_contains_login,
        "num_images": num_images,
        "images_host_mismatch": images_host_mismatch,
        "suspicious_keyword_count": suspicious_keyword_count,
        "anchor_to_body_ratio": round(anchor_to_body_ratio, 6),
    }
# src/parser.py (patch)
from bs4 import BeautifulSoup

def parse_html(html: str, url: str) -> dict:
    soup = BeautifulSoup(html, "lxml")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    metas = {}
    for m in soup.find_all("meta"):
        key = (m.get("name") or m.get("property") or "")
        if not key:
            continue
        key = str(key).strip()
        if not key:
            continue
        content = m.get("content")
        if content:
            metas[key] = content

    anchors = []
    for a in soup.find_all("a"):
        href = a.get("href") or ""
        text = a.get_text(strip=True) or ""
        anchors.append({"href": href, "text": text})

    forms = [
        {"action": (f.get("action") or ""), "method": (f.get("method") or "")}
        for f in soup.find_all("form")
    ]
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    body = soup.get_text(separator=" ", strip=True)[:2000]

    return {
        "title": title,
        "meta": metas,
        "anchors": anchors,
        "forms": forms,
        "scripts": scripts,
        "body_snippet": body,
    }
