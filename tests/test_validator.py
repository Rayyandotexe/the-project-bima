# tests/test_validator.py
import re
from src import validator


def test_validate_url_accepts_http_https():
    assert validator.validate_url("http://example.com")
    assert validator.validate_url("https://example.com")
    # trailing slash
    assert validator.validate_url("https://example.com/")

def test_validate_url_rejects_invalid():
    assert not validator.validate_url("")            # empty
    assert not validator.validate_url("ftp://x")     # scheme not allowed
    assert not validator.validate_url("javascript:;")# nonsense
    assert not validator.validate_url("http://")     # no domain

def test_iso_utc_now_format():
    s = validator.iso_utc_now()
    # ISO 8601 UTC format like 2025-12-11T05:49:57Z
    assert isinstance(s, str)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", s)

def test_validate_category_accepts_known_and_rejects_unknown():
    cats = validator.validate_category("phishing,spam")
    assert isinstance(cats, list)
    assert "phishing" in cats and "spam" in cats

    none = validator.validate_category("not-a-real-category")
    assert none is None

def test_normalize_record_defaults_and_types():
    rec = {"url": "https://example.com", "category": "phishing"}
    n = validator.normalize_record(rec)
    assert n["url"] == "https://example.com"
    assert "discovered" in n and isinstance(n["discovered"], str)
    assert isinstance(n["category"], list)
    assert n["status"] in (0, 1)
    assert isinstance(n["confidence_level"], int)
    assert n["brand"] == "-" or isinstance(n["brand"], str)
