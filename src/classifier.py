from typing import Dict, Any, Optional, Tuple, List
import logging
from pathlib import Path
import pandas as pd
from urllib.parse import urlparse

from .crawler import crawl, CrawlResult
from .model import predict_url as model_predict_url
from . import config
from .utils import sanitize_for_json  # import util yang dibuat

logger = logging.getLogger("bima.classifier")

# thresholds (fall back to config)
RULES_HIGH = getattr(config, "RULES_HIGH", 0.75)
RULES_LOW = getattr(config, "RULES_LOW", 0.20)
ML_HIGH = getattr(config, "ML_HIGH", 0.70)
ML_LOW = getattr(config, "ML_LOW", 0.30)
HYBRID_ALPHA = getattr(config, "HYBRID_ALPHA", 0.6)
RULES_OVERRIDE_THRESHOLD = getattr(config, "RULES_OVERRIDE_THRESHOLD", 0.8)
HYBRID_DECISION_THRESH = getattr(config, "HYBRID_DECISION_THRESH", 0.7)

# Simple dataset cache to act as safety-net
DATASET_CACHE = {"urls": set(), "domains": set(), "_loaded": False}

def _load_dataset_cache():
    if DATASET_CACHE["_loaded"]:
        return
    datasets_dir = Path(__file__).resolve().parent.parent / "datasets"
    for csv in datasets_dir.glob("*.csv"):
        try:
            df = pd.read_csv(csv)
        except Exception:
            continue
        cols = [c.lower() for c in df.columns]
        if "url" not in cols:
            continue
        label_col = next((c for c in cols if c in ("type", "label", "class")), None)
        for _, r in df.iterrows():
            try:
                url = str(r.get("url") or r.get("URL") or "").strip()
            except Exception:
                continue
            if not url:
                continue
            lbl = str(r.get(label_col or "type", "")).strip().lower() if label_col else ""
            if lbl in ("phishing", "malicious", "scam", "fraud", "phish", "bad"):
                DATASET_CACHE["urls"].add(url)
                try:
                    host = urlparse(url).hostname
                    if host:
                        DATASET_CACHE["domains"].add(host.lower())
                except Exception:
                    pass
    DATASET_CACHE["_loaded"] = True

# ----------------- helpers -----------------
def _safe_ml_predict(url: str, page_features: Optional[Dict[str, Any]] = None) -> Tuple[int, float, int]:
    try:
        try:
            out = model_predict_url(url, page_features)
        except TypeError:
            out = model_predict_url(url)
    except Exception:
        raise
    if isinstance(out, tuple) and len(out) >= 2:
        label = int(out[0])
        proba = float(out[1])
        conf = int(out[2]) if len(out) > 2 else int(round(proba * 100))
        return label, proba, conf
    raise RuntimeError("Unexpected ML output format from model_predict_url")

def _ml_block(label: int, proba: float, conf: int) -> Dict[str, Any]:
    return {
        "label": int(label),
        "probability": float(proba),
        "confidence": int(conf),
    }

def _combine_scores(ml_proba: float, rules_score: float, alpha: float = HYBRID_ALPHA) -> float:
    ml = max(0.0, min(1.0, float(ml_proba or 0.0)))
    rules = max(0.0, min(1.0, float(rules_score or 0.0)))
    return float(alpha * ml + (1.0 - alpha) * rules)

def _interpret_score(final_proba: float) -> str:
    if final_proba >= HYBRID_DECISION_THRESH:
        return "PHISHING"
    if final_proba <= (1.0 - HYBRID_DECISION_THRESH):
        return "LEGIT"
    return "SUSPICIOUS"

def evaluate_rules(crawl_res: CrawlResult) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    if crawl_res is None:
        return 0.0, reasons

    try:
        score = float(getattr(crawl_res, "rules_score", 0.0) or 0.0)
    except Exception:
        score = 0.0

    if getattr(crawl_res, "status", "") in ("error", "blocked"):
        reasons.append("crawler_error_or_blocked")
    rl = getattr(crawl_res, "rules_label", None)
    if rl:
        reasons.append(f"rules_label={rl}")
    parsed = getattr(crawl_res, "parsed", {}) or {}
    # prefer rules_reasons attached by crawler; fall back to inspecting parsed
    try:
        if isinstance(parsed, dict) and "rules_reasons" in parsed:
            rr = parsed.get("rules_reasons") or []
            if rr:
                reasons.extend(rr if isinstance(rr, list) else [rr])
        else:
            # legacy: parsed may itself be the parsed_html dict
            anchors = parsed.get("anchors", []) or []
            if anchors:
                reasons.append(f"anchors_count={len(anchors)}")
            forms = parsed.get("forms", []) or []
            if forms:
                reasons.append(f"forms_count={len(forms)}")
            body = parsed.get("body_snippet") or ""
            if any(k in (body or "").lower() for k in ("login", "verify", "account", "secure")):
                reasons.append("body_contains_phishy_keywords")
    except Exception:
        pass

    return round(float(score), 4), reasons

# ----------------- sanitize final result helper -----------------
def _finalize_and_sanitize(result: Dict[str, Any]) -> Dict[str, Any]:
    crawler = result.get("crawler")
    if isinstance(crawler, dict):
        parsed = crawler.get("parsed") or crawler.get("page_features") or {}
        crawler["parsed"] = sanitize_for_json(parsed)
    if "ml" in result and isinstance(result["ml"], dict):
        result["ml"] = sanitize_for_json(result["ml"])
    if "rules" in result and isinstance(result["rules"], dict):
        result["rules"] = sanitize_for_json(result["rules"])
    return result

# ----------------- main pipeline -----------------
def classify_url(url: str, capture_screenshot: bool = False) -> Dict[str, Any]:
    logger.info("Classify URL: %s", url)

    try:
        _load_dataset_cache()
    except Exception:
        logger.debug("Dataset cache load failed (non-fatal)")

    result: Dict[str, Any] = {
        "url": url,
        "crawler": None,
        "rules": None,
        "ml": None,
        "final_stage": "unknown",
        "final_label": "UNKNOWN",
        "final_score": 0.0,
        "source": None,
        "error": None,
    }

    try:
        crawl_res: CrawlResult = crawl(url, capture_screenshot=capture_screenshot)
    except Exception as e:
        logger.exception("Crawler threw exception for %s", url)
        try:
            lbl, proba, conf = _safe_ml_predict(url)
            result["ml"] = _ml_block(lbl, proba, conf)
            result.update({
                "final_stage": "ml_fallback_exception",
                "final_label": "PHISHING" if lbl == 1 else "LEGIT",
                "final_score": float(proba),
                "source": "ml",
                "error": f"crawler exception: {e}"
            })
            return _finalize_and_sanitize(result)
        except Exception as me:
            logger.exception("ML fallback also failed for %s", url)
            result.update({
                "final_stage": "error",
                "final_label": "UNKNOWN",
                "final_score": 0.0,
                "source": "error",
                "error": f"crawler exception and ml fallback failed: {me}"
            })
            return _finalize_and_sanitize(result)

    try:
        result["crawler"] = crawl_res.to_dict() if hasattr(crawl_res, "to_dict") else crawl_res.__dict__
    except Exception:
        result["crawler"] = {
            "url": getattr(crawl_res, "url", url),
            "status": getattr(crawl_res, "status", "error"),
            "rules_score": getattr(crawl_res, "rules_score", 0.0),
            "rules_label": getattr(crawl_res, "rules_label", None),
            "parsed": getattr(crawl_res, "parsed", None),
            "error": getattr(crawl_res, "error", None),
        }

    if not getattr(crawl_res, "reachable", True) or getattr(crawl_res, "status", "") in ("error", "blocked"):
        try:
            lbl, proba, conf = _safe_ml_predict(url, page_features=(getattr(crawl_res, "parsed", None) or {}))
            result["ml"] = _ml_block(lbl, proba, conf)
            result.update({
                "final_stage": "ml_fallback_unreachable",
                "final_label": "PHISHING" if lbl == 1 else "LEGIT",
                "final_score": float(proba),
                "source": "ml",
                "error": getattr(crawl_res, "error", None)
            })
            return _finalize_and_sanitize(result)
        except Exception as e:
            logger.exception("ML fallback failed (soft) for %s", url)
            result.update({
                "final_stage": "error",
                "final_label": "UNKNOWN",
                "final_score": 0.0,
                "source": "error",
                "error": f"ml fallback error: {e}"
            })
            return _finalize_and_sanitize(result)

    rules_score, rules_reasons = evaluate_rules(crawl_res)
    result["rules"] = {"score": rules_score, "reasons": rules_reasons}

    if rules_score >= RULES_OVERRIDE_THRESHOLD:
        result.update({
            "final_stage": "rules_override",
            "final_label": "PHISHING",
            "final_score": float(rules_score),
            "source": "rules"
        })
        return _finalize_and_sanitize(result)

    rs_label = getattr(crawl_res, "rules_label", None)
    if rs_label:
        rl = str(rs_label).lower()
        if rl == "phishing" and rules_score >= RULES_HIGH:
            result.update({
                "final_stage": "rules",
                "final_label": "PHISHING",
                "final_score": float(rules_score),
                "source": "rules"
            })
            return _finalize_and_sanitize(result)
        if rl == "legit" and rules_score <= RULES_LOW:
            result.update({
                "final_stage": "rules",
                "final_label": "LEGIT",
                "final_score": 1.0 - float(rules_score),
                "source": "rules"
            })
            return _finalize_and_sanitize(result)

    try:
        lbl, proba, conf = _safe_ml_predict(url, page_features=(getattr(crawl_res, "parsed", None) or {}))
        result["ml"] = _ml_block(lbl, proba, conf)

        if proba >= ML_HIGH:
            final_proba = proba
            final_label = "PHISHING"
            source = "ml"
        elif proba <= ML_LOW:
            final_proba = proba
            final_label = "LEGIT"
            source = "ml"
        else:
            final_proba = _combine_scores(proba, rules_score)
            final_label = _interpret_score(final_proba)
            source = "hybrid"

        result.update({
            "final_stage": "hybrid",
            "final_label": final_label,
            "final_score": round(float(final_proba), 4),
            "source": source
        })

        try:
            host = urlparse(url).hostname or ""
            if url in DATASET_CACHE["urls"] or (host and host.lower() in DATASET_CACHE["domains"]):
                if result["final_label"] != "PHISHING":
                    logger.info("Dataset contains URL/domain; forcing PHISHING for safety-net: %s", url)
                    result.update({
                        "final_label": "PHISHING",
                        "final_score": max(result["final_score"], 0.99),
                        "source": "dataset"
                    })
        except Exception:
            pass

        return _finalize_and_sanitize(result)
    except Exception as e:
        logger.exception("ML prediction failed for %s", url)
        if rules_score > 0:
            result.update({
                "final_stage": "rules_fallback",
                "final_label": "PHISHING" if rules_score >= 0.5 else "SUSPICIOUS",
                "final_score": float(rules_score),
                "source": "rules",
                "error": f"ml error: {e}"
            })
            return _finalize_and_sanitize(result)
        result.update({
            "final_stage": "error",
            "final_label": "UNKNOWN",
            "final_score": 0.0,
            "source": "error",
            "error": f"ml error: {e}"
        })
        return _finalize_and_sanitize(result)
