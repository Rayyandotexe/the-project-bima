from __future__ import annotations

from typing import List, Any, Dict, Tuple
from urllib.parse import urlparse
from collections import Counter
import math
import re

try:
    import tldextract  # optional, improves hostname parsing
except Exception:
    tldextract = None

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "bank",
    "confirm", "password", "reset", "authenticate", "billing",
]

FREE_HOSTS = (
    "web.app", "vercel.app", "github.io", "netlify.app",
    "weeblysite.com", "getresponsepages.com", "pages.dev",
)

SUSPICIOUS_TLDS = (
    ".tk", ".ml", ".cf", ".gq", ".zip", ".click", ".review",
)

BRAND_TOKENS = (
    "google", "facebook", "paypal", "apple", "microsoft",
    "instagram", "amazon", "appleid", "outlook", "paypal-login",
)

IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

# ---------------------------------------------------------------------------
# Feature names (ordered) - keep in sync with extract_url_features
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    "url_length",               # total length of URL string
    "hostname_length",          # length of hostname
    "num_dots",                 # number of '.' in hostname
    "num_hyphens",             # number of '-' in hostname
    "num_subdirs",              # number of '/' in path
    "has_ip",                   # hostname is an IP address
    "has_at_symbol",            # '@' present in URL
    "has_https",                # URL starts with https://
    "suspicious_keyword_count", # count of suspicious keywords in whole URL
    "url_entropy",              # Shannon entropy of URL (higher -> more random)
    "hostname_entropy",         # entropy of hostname
    "free_host_service",        # hostname matches a known free hosting service (0/1)
    "suspicious_tld",           # hostname uses suspicious TLD (0/1)
    "numeric_chars_in_host",    # count of digit characters in hostname
    "brand_token_present",      # presence of known brand token in url/hostname
]

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Calculate Shannon entropy of string `s`.

    Returns 0.0 for empty input. This is cheap and useful to detect random-looking
    hostnames/paths used by automated hosting.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    probs = (count / length for count in counts.values())
    # safe numeric handling
    ent = -sum(p * math.log2(p) for p in probs if p > 0)
    return round(float(ent), 4)


def _extract_hostname(url: str) -> str:
    """Return the hostname for a URL using tldextract if available.

    Falls back to urlparse().hostname when tldextract isn't present.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host:
            return host
    except Exception:
        pass

    # tldextract may split subdomain+domain+suffix; use the full registered_domain
    if tldextract is not None:
        try:
            tx = tldextract.extract(url)
            # tx.registered_domain gives domain.suffix (or empty if none)
            reg = tx.registered_domain
            if reg:
                return reg
        except Exception:
            pass

    # crude fallback if everything else fails
    if "//" in url:
        try:
            return url.split("//", 1)[1].split("/", 1)[0]
        except Exception:
            return url
    return url


def _is_free_host(hostname: str) -> int:
    if not hostname:
        return 0
    h = hostname.lower()
    return 1 if any(h.endswith(s) or s in h for s in FREE_HOSTS) else 0


def _is_suspicious_tld(hostname: str) -> int:
    if not hostname:
        return 0
    h = hostname.lower()
    return 1 if any(h.endswith(t) for t in SUSPICIOUS_TLDS) else 0


def _brand_token_present(url: str, hostname: str) -> int:
    u = (url or "").lower()
    h = (hostname or "").lower()
    for token in BRAND_TOKENS:
        if token in u or token in h:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Main feature extraction API
# ---------------------------------------------------------------------------

def extract_url_features(url: str) -> List[Any]:
    """Extract ordered feature vector for `url`.

    Returned list follows the ordering in FEATURE_NAMES.
    Types are ints or floats (rounded), suitable for feeding into scikit-learn.
    """
    u = (url or "").strip()
    if not isinstance(u, str):
        u = str(u)

    hostname = _extract_hostname(u)
    path = ""
    try:
        parsed = urlparse(u)
        path = parsed.path or ""
    except Exception:
        path = ""

    url_length = len(u)
    hostname_length = len(hostname)
    num_dots = hostname.count('.')
    num_hyphens = hostname.count('-')
    num_subdirs = path.count('/')
    has_ip = 1 if IP_RE.match(hostname) else 0
    has_at_symbol = 1 if '@' in u else 0
    has_https = 1 if u.lower().startswith('https://') else 0
    lower = u.lower()
    suspicious_keyword_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in lower)

    url_entropy = _entropy(u)
    hostname_entropy = _entropy(hostname)
    free_host = _is_free_host(hostname)
    suspicious_tld = _is_suspicious_tld(hostname)
    numeric_chars_in_host = sum(1 for c in hostname if c.isdigit())
    brand_token = _brand_token_present(lower, hostname)

    values: List[Any] = [
        url_length,
        hostname_length,
        num_dots,
        num_hyphens,
        num_subdirs,
        has_ip,
        has_at_symbol,
        has_https,
        suspicious_keyword_count,
        url_entropy,
        hostname_entropy,
        free_host,
        suspicious_tld,
        numeric_chars_in_host,
        brand_token,
    ]

    return values


def extract_url_features_dict(url: str) -> Dict[str, Any]:
    """Return named feature mapping for a URL (useful for debugging / templates).

    NOTE: This uses FEATURE_NAMES extended to include the extra fields. If you
    rely on a specific numeric vector size for your model, make sure the model
    was trained on the same ordering and length.
    """
    vals = extract_url_features(url)
    # If lengths mismatch between FEATURE_NAMES and vals, create generated keys
    names = FEATURE_NAMES if len(FEATURE_NAMES) == len(vals) else [f"f{i}" for i in range(len(vals))]
    return dict(zip(names, vals))


# If module executed directly, quick demo
if __name__ == "__main__":
    samples = [
        "https://google.com",
        "http://example.login-secure-paypal.com/login",
        "https://thebestlinksfr.web.app/",
        "http://192.168.0.1/admin",
    ]
    for s in samples:
        print("---", s)
        print(extract_url_features_dict(s))
