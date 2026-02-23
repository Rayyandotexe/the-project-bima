# src/rules_engine.py
from urllib.parse import urlparse
import math

SHORT_URL_SERVICES = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
SUSPICIOUS_TLDS = [".tk", ".ml", ".cf", ".gq"]
SUSPECT_HOST_PATTERNS = [
    ".web.app", ".weeblysite.com", ".getresponsesite.com", ".webnode.com",
    ".wixsite.com", ".pages.dev", ".netlify.app", ".webflow.io", ".pages.dev",
    ".vercel.app", ".webflow.io", ".webself.net", ".getresponsepages.com"
]

from urllib.parse import urlparse
import math
import re

SHORT_URL_SERVICES = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
SUSPICIOUS_TLDS = [".tk", ".ml", ".cf", ".gq", ".zip", ".click"]
SUSPECT_HOST_PATTERNS = [
    ".web.app", ".weeblysite.com", ".getresponsesite.com", ".webnode.com",
    ".wixsite.com", ".pages.dev", ".netlify.app", ".webflow.io",
    ".vercel.app", ".webself.net", ".getresponsepages.com", "github.io"
]

SUSPICIOUS_PATH_RE = re.compile(r"(login|signin|verify|secure|update|confirm|account)", re.I)


def _hostname_entropy(host: str) -> float:
    if not host:
        return 0.0
    probs = {}
    for ch in host:
        probs[ch] = probs.get(ch, 0) + 1
    l = len(host)
    ent = 0.0
    for v in probs.values():
        p = v / l
        ent -= p * math.log2(p)
    return ent


def check_anchor_mismatch(parsed: dict) -> int:
    mismatches = 0
    anchors = parsed.get("anchors") or []
    for a in anchors:
        text = (a.get("text") or "").lower()
        href = (a.get("href") or "").lower()
        if not text or not href:
            continue
        # if anchor text contains keyword but href lacks it or points elsewhere, count mismatch
        if any(k in text for k in ("login", "signin", "bank", "paypal")) and not any(k in href for k in ("login", "signin", "bank", "paypal")):
            mismatches += 1
    return int(mismatches)


def rules_score(url: str, parsed: dict) -> tuple:
    """Compute 0.0 - 1.0 rules score and return (score, reasons).

    Returns (float, list[str]) where reasons are descriptive machine-friendly tags.
    """
    score = 0.0
    reasons = []
    parsed = parsed or {}
    host = (urlparse(url).netloc or "").lower()
    path = urlparse(url).path or ""

    # helper accessors
    anchors = parsed.get("anchors") or []
    forms = parsed.get("forms") or []
    scripts_inline = parsed.get("scripts_inline") or parsed.get("scripts") or []
    scripts_src = parsed.get("scripts_src") or []
    images = parsed.get("images") or []
    body_snippet = parsed.get("body_snippet") or ""
    page_features = parsed.get("page_features") or {}

    # 1) Shortener services
    if any(host == s or host.endswith('.' + s) for s in SHORT_URL_SERVICES):
        score += 0.4
        reasons.append("shortener_host")

    # 2) Suspicious TLDs
    if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
        score += 0.25
        reasons.append("suspicious_tld")

    # 3) Site-builder / free-host patterns
    if any(host.endswith(p) or p in host for p in SUSPECT_HOST_PATTERNS):
        score += 0.25
        reasons.append("site_builder_host")

    # 4) Anchor mismatches (text vs href)
    mism = int(check_anchor_mismatch(parsed) or 0)
    if mism > 0:
        add = min(0.2, 0.06 * mism)
        score += add
        reasons.append(f"anchor_mismatch:{mism}")

    # 5) Hostname entropy / numeric chars
    host_no_port = host.split(":")[0]
    ent = _hostname_entropy(host_no_port)
    if ent >= 3.5:
        score += 0.2
        reasons.append("host_entropy_high")
    elif ent >= 3.0:
        score += 0.1
        reasons.append("host_entropy_medium")
    digits = sum(1 for c in host_no_port if c.isdigit())
    if digits > 4:
        score += 0.15
        reasons.append("host_many_digits")

    # 6) Path keywords
    if SUSPICIOUS_PATH_RE.search(path):
        score += 0.08
        reasons.append("suspicious_path_keyword")

    # 7) Inline eval / suspicious scripts
    inline_code = "\n".join(scripts_inline)
    if "eval(" in inline_code or "document.write(" in inline_code:
        score += 0.12
        reasons.append("suspicious_inline_script")

    # 8) Forms / sensitive inputs and suspicious actions
    body_len = len(body_snippet)
    forms_with_password = 0
    form_sensitive = 0
    suspicious_actions = ("login.php", "auth.php", "verify.php", "signin.php", "login.html", "login.php")
    suspicious_action_found = None
    for f in forms:
        # parser may include 'sensitive' flag already
        if f.get("sensitive"):
            forms_with_password += 1
        # inputs
        inputs = f.get("inputs") or []
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            placeholder = (inp.get("placeholder") or "").lower()
            if any(tok in name or tok in placeholder for tok in ("card", "ccv", "cvv", "ssn", "otp", "password", "pin", "cardnumber")):
                form_sensitive += 1
        # check action filename
        action = (f.get("action") or "")
        if action:
            try:
                act_path = urlparse(action).path or ""
                fname = act_path.split("/")[-1].lower()
            except Exception:
                fname = ""
            if fname in suspicious_actions:
                suspicious_action_found = fname
    if forms_with_password >= 1:
        score += 0.25
        reasons.append("forms_with_password")
    if body_len < 200 and len(forms) > 0:
        score += 0.2
        reasons.append("short_body_with_form")
    if form_sensitive > 0:
        add = min(0.2, 0.05 * form_sensitive)
        score += add
        reasons.append(f"form_sensitive_count:{form_sensitive}")
    if suspicious_action_found:
        score += 0.25
        reasons.append(f"suspicious_form_action:{suspicious_action_found}")

    # 9) External scripts & images mismatches
    ext_scripts = 0
    for s in scripts_src:
        try:
            sh = urlparse(s).hostname or ""
        except Exception:
            sh = ""
        if sh and sh.lower() != host.lower():
            ext_scripts += 1
    if ext_scripts > 0:
        score += min(0.15, 0.05 * ext_scripts)
        reasons.append(f"external_scripts:{ext_scripts}")
    img_mismatch = 0
    for im in images:
        try:
            ih = urlparse(im).hostname or ""
        except Exception:
            ih = ""
        if ih and ih.lower() != host.lower():
            img_mismatch += 1
    if img_mismatch > 0:
        score += min(0.1, 0.03 * img_mismatch)
        reasons.append(f"image_mismatch:{img_mismatch}")

    # 10) Anchor density vs body length and hash anchors
    num_anchors = len(anchors)
    num_hash = sum(1 for a in anchors if (not a.get("href") or a.get("href") in ("#", "", "javascript:void(0)")))
    percent_hash = float(num_hash) / max(1.0, float(num_anchors)) if num_anchors else 0.0
    if num_anchors > 0:
        if body_len < 200 and num_anchors > 5:
            score += 0.08
            reasons.append("many_anchors_short_body")
        if percent_hash >= 0.5:
            score += 0.15
            reasons.append("hashy_anchors")

    # 11) URL length / many dots
    if len(url) > 120 or url.count(".") >= 5:
        score += 0.06
        reasons.append("long_or_many_dots")

    # 12) og:url / meta brand mismatch
    meta = parsed.get("meta") or {}
    og = meta.get("og:url") or meta.get("og:site_name") or meta.get("og:locale") or ""
    try:
        og_host = (urlparse(og).hostname or "").lower() if og else ""
    except Exception:
        og_host = ""
    if og_host and og_host != host:
        score += 0.30
        reasons.append("og_mismatch")
    # brand tokens in title/meta but host differs
    title = (parsed.get("title") or "").lower()
    brand_tokens = ("dana", "paypal", "bank", "ovo")
    for b in brand_tokens:
        if b in title and b not in host:
            score += 0.25
            reasons.append(f"brand_spoof:{b}")
            break

    # composite boosts
    if "og_mismatch" in reasons and any(r.startswith("suspicious_form_action") for r in reasons):
        score += 0.15
        reasons.append("og_and_form_composite")

    final = min(1.0, float(score))
    return final, reasons
