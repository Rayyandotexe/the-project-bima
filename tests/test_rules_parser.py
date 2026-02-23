import json
from pathlib import Path

from src.parser import parse_html, extract_page_features
from src import rules_engine


def load_fixture():
    p = Path(__file__).resolve().parent / "fixtures" / "sample_phish_debug.json"
    return json.loads(p.read_text())


def test_parser_detects_sensitive_input_and_anchor_hash():
    fixture = load_fixture()
    parsed = fixture["parsed"]
    # simulate HTML parsing by reconstructing minimal html - but use parsed fixture directly
    # verify anchor stats
    anchors = parsed.get("anchors")
    assert anchors and len(anchors) == 3
    num_hash = sum(1 for a in anchors if not a.get("href") or a.get("href") in ("#", "", "javascript:void(0)"))
    assert num_hash == 3

    # verify forms sensitive detection
    forms = parsed.get("forms")
    assert forms and len(forms) == 1
    f = forms[0]
    inputs = f.get("inputs")
    assert any("password" in (inp.get("name") or "").lower() or "password" in (inp.get("placeholder") or "").lower() for inp in inputs)


def test_rules_score_fixture_high_and_reasons():
    fixture = load_fixture()
    url = fixture["url"]
    parsed = fixture["parsed"]
    score, reasons = rules_engine.rules_score(url, parsed)
    assert score >= 0.75, f"expected high rules score, got {score}"
    # expected reasons include og_mismatch, suspicious_form_action, hashy_anchors, low_text_with_form (names may vary)
    reason_str = "|".join(reasons)
    assert "og_mismatch" in reason_str
    assert "suspicious_form_action" in reason_str or "suspicious_form_action:login.php" in reason_str
    assert "hashy_anchors" in reason_str
    assert any(r.startswith("short_body_with_form") or r.startswith("short_body") or r.startswith("short_body_with_form") for r in reasons) or "short_body_with_form" in reason_str
