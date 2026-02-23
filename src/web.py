# src/web.py
try:
    from flask import Flask, render_template, request, jsonify, make_response
except Exception:
    print("[ERROR] Flask is not installed in your environment. Install with: pip install flask")
    raise
import logging
import time
import copy
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from src.classifier import classify_url
from src.model import explain_decision, load_model_safe

# try import sanitizer util (if you added src/utils.py). Otherwise provide fallback.
try:
    from src.utils import sanitize_for_json
except Exception:
    def sanitize_for_json(obj: Any) -> Any:
        """Best-effort fallback sanitizer (simple)."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k is None:
                    continue
                out[str(k)] = sanitize_for_json(v)
            return out
        if isinstance(obj, (list, tuple, set)):
            return [sanitize_for_json(x) for x in obj]
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        try:
            return str(obj)
        except Exception:
            return None

app = Flask(__name__, template_folder="../templates")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bima.web")

# Simple in-memory cache for recent classification results
CACHE_TTL = 30.0  # seconds
RESULT_CACHE: Dict[str, Dict[str, Any]] = {}

# Per-IP simple rate limiter (sliding window)
RATE_WINDOW = 60.0  # seconds
RATE_LIMIT = 30     # requests per window per IP
IP_REQS: Dict[str, Dict[str, Any]] = {}  # ip -> {"count": int, "start": float}


def _client_key() -> str:
    """Return remote client IP (best-effort)."""
    xf = request.headers.get("X-Forwarded-For")
    if xf:
        return xf.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _rate_limit_check() -> Optional[Any]:
    """Return None if allowed, or a Flask response if rate-limited."""
    key = _client_key()
    now = time.time()
    rec = IP_REQS.get(key)
    if rec is None or (now - rec["start"]) > RATE_WINDOW:
        IP_REQS[key] = {"count": 1, "start": now}
        return None
    rec["count"] += 1
    if rec["count"] > RATE_LIMIT:
        retry_after = int(RATE_WINDOW - (now - rec["start"]))
        return make_response(jsonify({"error": "rate_limited", "retry_after": retry_after}), 429)
    return None


def _cache_get(url: str) -> Optional[Dict[str, Any]]:
    e = RESULT_CACHE.get(url)
    if not e:
        return None
    if (time.time() - e["ts"]) > CACHE_TTL:
        RESULT_CACHE.pop(url, None)
        return None
    return copy.deepcopy(e["result"])


def _cache_set(url: str, result: Dict[str, Any]) -> None:
    RESULT_CACHE[url] = {"result": copy.deepcopy(result), "ts": time.time()}


def _normalize_result_shape(r: Optional[dict]) -> dict:
    """
    Ensure result dict always contains keys the template/API expects,
    and sanitize nested structures for safe JSON rendering.
    """
    base = {
        "url": None,
        "crawler": None,
        "rules": None,
        "ml": None,
        "final_stage": None,
        "final_label": None,
        "final_score": None,
        "source": None,
        "error": None,
    }
    out: dict = dict(base)
    if not r:
        return out

    # copy top-level keys (prefer values from r)
    for k in base.keys():
        out[k] = r.get(k, base[k])

    # normalize crawler sub-structure
    crawler = out.get("crawler")
    if isinstance(crawler, dict):
        safe_crawler = {
            "url": crawler.get("url"),
            "status": crawler.get("status"),
            "status_code": crawler.get("status_code"),
            "content_length": crawler.get("content_length"),
            "reachable": crawler.get("reachable"),
            "rules_score": crawler.get("rules_score"),
            "rules_label": crawler.get("rules_label"),
            "error": crawler.get("error"),
            "screenshot": crawler.get("screenshot"),
        }
        # sanitize parsed/page_features
        parsed = crawler.get("parsed") or crawler.get("page_features") or {}
        safe_crawler["parsed"] = sanitize_for_json(parsed if parsed is not None else {})
        out["crawler"] = safe_crawler
    else:
        out["crawler"] = None

    # normalize rules block (if classifier provided separate rules dict)
    rules = out.get("rules")
    if isinstance(rules, dict):
        safe_rules = {
            "score": rules.get("score"),
            "reasons": sanitize_for_json(rules.get("reasons") or []),
        }
        out["rules"] = safe_rules
    else:
        out["rules"] = None

    # normalize ML block
    ml = out.get("ml")
    if isinstance(ml, dict):
        try:
            label = int(ml.get("label", 0)) if ml.get("label") is not None else None
        except Exception:
            label = None
        try:
            prob = float(ml.get("probability")) if ml.get("probability") is not None else None
        except Exception:
            prob = None
        try:
            conf = int(ml.get("confidence", 0)) if ml.get("confidence") is not None else None
        except Exception:
            conf = None
        out["ml"] = {
            "label": label,
            "probability": prob,
            "confidence": conf,
        }
    else:
        out["ml"] = None

    # sanitize final_score (float or None)
    try:
        out["final_score"] = float(out["final_score"]) if out["final_score"] is not None else None
    except Exception:
        out["final_score"] = None

    # ensure strings for top-level fields
    out["final_stage"] = out["final_stage"] or None
    out["final_label"] = out["final_label"] or None
    out["source"] = out["source"] or None
    out["error"] = out["error"] or None
    out["url"] = out["url"] or None

    return out


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        rl = _rate_limit_check()
        if rl:
            return rl

        url = request.form.get("url", "").strip()
        if not url:
            result = {"status": "error", "error": "URL tidak boleh kosong"}
        else:
            url = _ensure_scheme(url)
            try:
                cached = _cache_get(url)
                if cached:
                    result = cached
                    logger.info("Cache hit for %s", url)
                else:
                    # request screenshot capture for web UI so operator can view evidence
                    raw = classify_url(url, capture_screenshot=True)
                    result = _normalize_result_shape(raw)
                    _cache_set(url, result)
            except Exception as e:
                logger.exception("Unhandled error in web layer for %s", url)
                result = {"status": "error", "error": f"Internal error: {e}"}

    return render_template("index.html", result=result)


@app.route("/api/scan", methods=["GET", "POST"])
def api_scan():
    rl = _rate_limit_check()
    if rl:
        return rl

    if request.method == "GET":
        url = request.args.get("url", "").strip()
    else:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()

    if not url:
        return make_response(jsonify({"error": "missing url"}), 400)

    url = _ensure_scheme(url)

    try:
        cached = _cache_get(url)
        if cached:
            logger.info("API cache hit for %s", url)
            return jsonify({"cached": True, "result": cached})
        # For API clients, also capture screenshot by default so UI can show evidence.
        # (This can be heavy; consider changing to an optional parameter later.)
        raw = classify_url(url, capture_screenshot=True)
        result = _normalize_result_shape(raw)
        _cache_set(url, result)
        return jsonify({"cached": False, "result": result})
    except Exception as e:
        logger.exception("API scan failed for %s", url)
        return make_response(jsonify({"error": f"internal error: {e}"}), 500)


@app.route("/api/inspect", methods=["GET"])
def api_inspect():
    rl = _rate_limit_check()
    if rl:
        return rl

    url = request.args.get("url", "").strip()
    if not url:
        return make_response(jsonify({"error": "missing url"}), 400)

    url = _ensure_scheme(url)
    try:
        model, meta = load_model_safe()
    except Exception:
        model, meta = None, None

    try:
        ed = explain_decision(url)
        # sanitize explain output too
        ed_sanitized = sanitize_for_json(ed or {})
        return jsonify({"model_meta": meta, "explain": ed_sanitized})
    except Exception as e:
        logger.exception("Explain failed for %s", url)
        return make_response(jsonify({"error": f"explain failed: {e}"}), 500)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": int(time.time())})


def _ensure_scheme(url: str) -> str:
    """Make sure URL starts with http/https for validator/crawler."""
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "http://" + url


def run(host: str = "127.0.0.1", port: int = 5000, debug: bool = True):
    logger.info("Starting web app on %s:%s (debug=%s)", host, port, debug)
    app.run(debug=debug, host=host, port=port)


if __name__ == "__main__":
    run()
