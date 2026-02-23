import json
from pathlib import Path

from src import classifier


def load_fixture():
    p = Path(__file__).resolve().parent / "fixtures" / "sample_phish_debug.json"
    return json.loads(p.read_text())


def test_integration_classify_fixture(monkeypatch):
    fixture = load_fixture()
    url = fixture["url"]
    parsed = fixture["parsed"]

    # Monkeypatch crawl to return an object-like with expected attrs
    class Dummy:
        def __init__(self, url, parsed):
            self.url = url
            self.status = "ok"
            self.status_code = 200
            self.content_length = len(parsed.get("body_snippet") or "")
            self.reachable = True
            # classifier.evaluate_rules expects parsed to possibly include rules_reasons
            self.parsed = {"parsed_html": parsed, "page_features": parsed.get("page_features", {}), "rules_reasons": []}
            self.rules_score = 0.0
            self.rules_label = "uncertain"
            self.error = None

    def fake_crawl(u):
        return Dummy(url, parsed)

    monkeypatch.setattr(classifier, "crawl", fake_crawl)

    out = classifier.classify_url(url)
    # Expect rules reasons present in returned structure (classifier attaches them)
    assert "rules" in out and isinstance(out["rules"], dict)
    # When pipeline runs, due to patched crawl, classifier may fall back to ML; ensure output is serializable
    assert "final_label" in out
