# tests/test_parser.py
from src import parser

SAMPLE_HTML = """
<!doctype html>
<html>
  <head>
    <title>Test Page</title>
    <meta name="description" content="sample description">
    <meta property="og:title" content="OG Test">
  </head>
  <body>
    <h1>Hello</h1>
    <a href="https://example.com/login">Login</a>
    <a href="https://malicious.com">Click me</a>
    <form action="/submit" method="post"><input name="q"></form>
    <script src="https://cdn.example.com/lib.js"></script>
    <p>Some body text here.</p>
  </body>
</html>
"""

def test_parse_html_has_title_and_meta():
    parsed = parser.parse_html(SAMPLE_HTML, "https://example.com")
    assert parsed["title"] == "Test Page"
    assert isinstance(parsed["meta"], dict)
    assert parsed["meta"].get("description") == "sample description" or parsed["meta"].get("og:title") == "OG Test"

def test_parse_html_extracts_anchors_forms_scripts_body():
    parsed = parser.parse_html(SAMPLE_HTML, "https://example.com")
    anchors = parsed.get("anchors", [])
    assert any(a["href"] == "https://example.com/login" for a in anchors)
    assert any(a["href"] == "https://malicious.com" for a in anchors)
    forms = parsed.get("forms", [])
    assert len(forms) == 1
    scripts = parsed.get("scripts", [])
    assert "https://cdn.example.com/lib.js" in scripts
    assert "Some body text here." in parsed.get("body_snippet", "")
