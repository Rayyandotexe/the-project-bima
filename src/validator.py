import validators
from urllib.parse import urlparse
import tldextract
from datetime import datetime

from .config import CATEGORY_LIST
def validate_url(url: str) -> bool:
    """Return True jika URL valid, False jika tidak."""
    
    # Cek kosong / bukan string
    if not url or not isinstance(url, str):
        return False

    url = url.strip()

    # Harus mulai dengan http/https
    if not (url.startswith('http://') or url.startswith('https://')):
        return False

    # Validasi general URL menggunakan library validators
    if not validators.url(url):
        return False

    # Validasi domain struktur (syntactic)
    extracted = tldextract.extract(url)
    if not extracted.domain:
        return False

    return True

def iso_utc_now() -> str:
    """Return timestamp UTC ISO-8601 format ex: 2025-01-01T12:00:00Z"""
    return datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
def validate_category(categories):
    """
    Input bisa berupa:
    - string "phishing, fraud"
    - list ["phishing","fraud"]
    
    Output: list kategori yang valid ATAU None
    """
    
    if isinstance(categories, str):
        cats = [c.strip().lower() for c in categories.split(',') if c.strip()]
    else:
        cats = [c.strip().lower() for c in categories]

    # Filter kategori yang valid
    valid = [c for c in cats if c in CATEGORY_LIST]

    return valid if valid else None

def normalize_record(rec: dict) -> dict:
    """Pastikan record memiliki field lengkap dan normalisasi value."""

    normalized = {}

    # URL
    normalized['url'] = rec.get('url', '').strip()

    # Timestamp discovered
    normalized['discovered'] = rec.get('discovered') or iso_utc_now()

    # Category
    cats = validate_category(rec.get('category', 'phishing'))
    normalized['category'] = cats or ['phishing']

    # Source
    normalized['source'] = rec.get('source', 'crawling')

    # Status/resolved: 0 atau 1
    normalized['status'] = int(rec.get('status', 0))
    normalized['resolved'] = int(rec.get('resolved', 0))

    # Confidence level 0–100
    cl = rec.get('confidence_level', 0)
    try:
        cl = int(cl)
    except:
        cl = 0

    normalized['confidence_level'] = max(0, min(100, cl))

    # Brand (default “-”)
    normalized['brand'] = rec.get('brand', '-') or '-'

    # Screenshot link atau base64
    normalized['screenshots'] = rec.get('screenshots', None)

    return normalized

def classify(score: int) -> str:
    """
    Klasifikasi akhir dari skor deteksi.
    - score >= 70: PHISHING
    - 40 <= score < 70: SUSPICIOUS
    - score < 40: LEGITIMATE
    """
    if score >= 70:
        return "PHISHING"
    elif score >= 40:
        return "SUSPICIOUS"
    else:
        return "LEGITIMATE"
