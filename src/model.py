# src/model.py
from __future__ import annotations
import json
import re
import math
import platform
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Any, Dict

import pandas as pd
import numpy as np
import joblib
import logging

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

try:
    from sklearn.calibration import CalibratedClassifierCV
except Exception:
    CalibratedClassifierCV = None

logger = logging.getLogger("bima.model")

# ---------- simple heuristics lists ----------
SHORT_URL_SERVICES = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
SUSPICIOUS_TLDS = [".tk", ".ml", ".cf", ".gq", ".zip", ".click"]
SUSPECT_HOST_PATTERNS = [
    ".web.app", ".weeblysite.com", ".getresponsesite.com", ".webflow.io",
    ".wixsite.com", ".vercel.app", ".netlify.app", "github.io", "000webhostapp.com"
]

IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "bank", "confirm", "signin"]

# ---------- PATHS ----------
MODEL_PATH = Path(__file__).resolve().parent / "trained_model.pkl"
META_PATH = Path(__file__).resolve().parent / "trained_model_meta.json"
DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"

# ---------- FEATURE SPEC ----------
URL_FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "num_dots",
    "num_hyphens",
    "num_subdirs",
    "has_ip",
    "has_at_symbol",
    "has_https",
    "suspicious_keyword_count",
    "hostname_entropy",
    "num_digits_in_host",
    "is_shortener",
    "suspicious_tld",
    "path_token_count",
]

PAGE_FEATURE_NAMES: List[str] = [
    "page_body_len",
    "num_anchors",
    "num_forms",
    "num_external_links",
    "has_password_input",
    "num_scripts",
    "title_len",
    "page_suspicious_keywords",
    # additional crawler features
    "forms_with_password",
    "external_link_ratio",
    "redirect_count",
]

FEATURE_NAMES: List[str] = URL_FEATURE_NAMES + PAGE_FEATURE_NAMES

# allow optional external features module
try:
    from .features import extract_url_features as _features_from_module  # type: ignore
except Exception:
    _features_from_module = None

# optional crawler-backed page features
try:
    from .crawler import crawl
except Exception:
    crawl = None


# ------------------ UTIL / FEATURE HELPERS ------------------
def _extract_hostname(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "")
    except Exception:
        if "//" in url:
            try:
                return url.split("//", 1)[1].split("/", 1)[0]
            except Exception:
                return url
        return url


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    probs = [v / len(s) for v in counts.values()]
    ent = -sum(p * math.log2(p) for p in probs if p > 0)
    return round(float(ent), 4)


def _is_shortener_host(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    # require exact-match or suffix match to avoid matching substrings inside legitimate hosts
    return any(host == s or host.endswith('.' + s) for s in SHORT_URL_SERVICES)


def _has_suspicious_tld(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(host.endswith(t) for t in SUSPICIOUS_TLDS)


def _count_path_tokens(path: str) -> int:
    if not path:
        return 0
    return len([p for p in path.split("/") if p.strip()])


# ------------------ FEATURE EXTRACTION (URL + optional page features) ------------------
def extract_features(url: str, page_features: Optional[Dict[str, Any]] = None) -> List[float]:
    """
    Return a feature vector (URL features followed by page features).
    If page_features not provided, page fields are appended as zeros.
    Order must match FEATURE_NAMES.
    """
    # allow external implementation override (if provided)
    if _features_from_module is not None and page_features is None:
        try:
            out = _features_from_module(url)
            # ensure result is a list of floats/ints
            return [float(x) for x in out]
        except Exception:
            # fallback to builtin
            pass

    if not isinstance(url, str):
        url = str(url or "")

    u = url.strip()
    from urllib.parse import urlparse
    parsed = urlparse(u)
    hostname = _extract_hostname(u) or ""
    host_only = hostname.split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""

    # URL-only features
    url_length = len(u)
    hostname_length = len(hostname)
    num_dots = hostname.count(".")
    num_hyphens = hostname.count("-")
    num_subdirs = path.count("/")
    has_ip = int(bool(IP_RE.match(host_only)))
    has_at_symbol = int("@" in u)
    has_https = int(u.lower().startswith("https://"))
    lower = u.lower()
    suspicious_keyword_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in lower)

    hostname_entropy = _shannon_entropy(host_only)
    num_digits_in_host = sum(1 for ch in host_only if ch.isdigit())
    is_shortener = int(_is_shortener_host(host_only))
    suspicious_tld = int(_has_suspicious_tld(host_only))
    path_token_count = _count_path_tokens(path)

    url_feats: List[float] = [
        float(url_length),
        float(hostname_length),
        float(num_dots),
        float(num_hyphens),
        float(num_subdirs),
        float(has_ip),
        float(has_at_symbol),
        float(has_https),
        float(suspicious_keyword_count),
        float(hostname_entropy),
        float(num_digits_in_host),
        float(is_shortener),
        float(suspicious_tld),
        float(path_token_count),
    ]

    # Page-level features: read from page_features dict if provided, otherwise zeros
    page_feats: List[float] = []
    if page_features and isinstance(page_features, dict):
        def getp(k):
            v = page_features.get(k, 0)
            try:
                return float(v)
            except Exception:
                return 0.0
        page_feats = [
            getp("body_len"),
            getp("num_anchors"),
            getp("num_forms"),
            getp("num_external_links"),
            float(1.0 if page_features.get("has_password_input") else 0.0),
            getp("num_scripts"),
            getp("title_len"),
            getp("suspicious_keyword_count"),
            getp("forms_with_password"),
            getp("external_link_ratio"),
            getp("redirect_count"),
        ]
    else:
        page_feats = [0.0] * len(PAGE_FEATURE_NAMES)

    return url_feats + page_feats


# ------------------ DATASET HELPERS ------------------
def _read_dataset_file(path: Path) -> pd.DataFrame:
    # Try a normal read first, then fall back to a more permissive parser
    try:
        df = pd.read_csv(path, dtype=str, low_memory=False)
    except Exception as e:
        print(f"[WARN] initial read failed for {path}: {e}; retrying with python engine and skipping bad lines")
        try:
            # 'low_memory' is not supported with the python engine; omit it here
            df = pd.read_csv(path, dtype=str, engine="python", on_bad_lines="skip", sep=",")
        except Exception as e2:
            print(f"[ERROR] failed to read {path}: {e2}")
            raise
    df.columns = [c.lower() for c in df.columns]

    # If dataset file has no 'type' column but filename indicates a phishing feed,
    # add a default 'type' column marking all rows as phishing. This handles
    # cases like 'phishing_NEW.csv' converted from .txt without a type field.
    try:
        if "type" not in df.columns:
            name = Path(path).name.lower()
            if "phish" in name or name.startswith("phishing"):
                df["type"] = "phishing"
    except Exception:
        pass

    return df


def _normalize_label_col(series: pd.Series) -> pd.Series:
    """
    Normalize label values to 0 (legit) or 1 (phishing).
    Unknowns -> np.nan so we can drop them.
    """
    phishing_set = {"phishing", "malicious", "fraud", "spam", "scam", "phish", "bad", "attack", "malware", "defacement", "1"}
    legit_set = {"legit", "legitimate", "benign", "safe", "normal", "good", "trusted", "clean", "0"}

    def _map(v):
        if pd.isna(v):
            return np.nan
        if isinstance(v, (int, np.integer, float, np.floating)):
            try:
                return 1 if int(v) == 1 else 0
            except Exception:
                return np.nan
        if not isinstance(v, str):
            return np.nan
        s = v.strip().lower()
        # split on non-alphanumeric to handle combined labels like "phishing, fraud"
        tokens = [t for t in re.split(r'[^a-z0-9]+', s) if t]
        for t in tokens:
            if t in phishing_set:
                return 1
            if t in legit_set:
                return 0
        # fallback: check whole string membership
        if s in phishing_set:
            return 1
        if s in legit_set:
            return 0
        return np.nan
    return series.apply(_map)


def _make_metadata(model, feature_names: List[str], X_shape: Tuple[int, int], y_counts: Dict[int, int]) -> dict:
    import sklearn
    return {
        "created_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "python_version": platform.python_version(),
        "sklearn_version": getattr(sklearn, "__version__", ""),
        "pandas_version": getattr(pd, "__version__", ""),
        "numpy_version": getattr(np, "__version__", ""),
        "feature_names": feature_names,
        "X_shape": X_shape,
        "label_counts": y_counts,
    }


def save_model_and_metadata(model, meta: dict) -> None:
    joblib.dump(model, MODEL_PATH)
    with open(META_PATH, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)


# ------------------ TRAIN ------------------
def train_model(dataset_path: Optional[str] = None,
                calibrate: bool = False,
                test_size: float = 0.2,
                balance: bool = True,
                use_page_features: bool = False,
                checkpoint_path: Optional[str] = None,
                resume: bool = False) -> None:
    """
    Train random forest on combined datasets found in DATASETS_DIR or a specific path.
    - If the dataset(s) only contain phishing examples (no label column), we attempt to
      set label=1 for those rows. However ideally the dataset should contain both classes.
    """
    print("=== TRAINING MODEL ===")
    dfs: List[pd.DataFrame] = []
    if dataset_path:
        p = Path(dataset_path)
        if not p.exists():
            raise FileNotFoundError(f"Provided dataset not found: {p}")
        print(f"Loading {p}...")
        dfs.append(_read_dataset_file(p))
    else:
        # Auto-load all CSV files in the datasets directory so new files
        # like 'phishing_NEW_urls.csv' are picked up without renaming.
        for p in sorted(DATASETS_DIR.glob("*.csv")):
            try:
                print(f"Loading {p}...")
                dfs.append(_read_dataset_file(p))
            except Exception as e:
                print(f"[WARN] Failed to load {p}: {e}")

    if not dfs:
        raise FileNotFoundError(f"No dataset files found in {DATASETS_DIR} and no dataset_path provided")

    df = pd.concat(dfs, ignore_index=True)
    print(f"Total combined samples: {len(df)}")

    url_col = next((c for c in df.columns if c in ("url", "link", "location")), None)
    type_col = next((c for c in df.columns if c in ("type", "label", "class")), None)

    if not url_col:
        raise ValueError("Dataset missing URL column (expected 'url' or 'link')")

    # If dataset has no label column, assume phishing-only feed (best-effort)
    if not type_col:
        df["label"] = 1
        type_col = "label"
        print("[INFO] No label column detected: marking rows as phishing=1 (phishing-only feed)")

    df = df.dropna(subset=[url_col])

    # Normalize labels (unknown -> NaN)
    df["label"] = _normalize_label_col(df[type_col])
    print("Raw label distribution (example values):")
    print(df[type_col].value_counts(dropna=False).head(10).to_dict())
    print("Normalized label counts (incl NaN):")
    print(df["label"].value_counts(dropna=False).to_dict())

    before = len(df)
    df = df.dropna(subset=["label"])
    after = len(df)
    print(f"Filtered invalid labels: {before} -> {after} rows kept")
    if after == 0:
        raise ValueError("No valid labeled rows remain after normalization.")

    # Build X (features) and y
    X_list: List[List[float]] = []
    misses = 0

    # feature cache (checkpoint) to allow interrupt/resume without losing extraction work
    # By default use DATASETS_DIR/feature_cache.npz unless user specified a checkpoint path
    cache_path = Path(checkpoint_path) if checkpoint_path else (DATASETS_DIR / "feature_cache.npz")
    if cache_path.exists():
        try:
            if resume:
                print(f"[INFO] Found feature cache: {cache_path}; loading cached features (resume)...")
                loaded = np.load(cache_path, allow_pickle=True)
                X_arr = loaded["X"]
                y_arr = loaded["y"]
                # basic sanity check length
                if len(y_arr) == len(X_arr):
                    X_list = [list(row) for row in X_arr]
                    y = y_arr.astype(int)
                    print(f"[INFO] Loaded {len(X_list)} feature vectors from cache; skipping extraction")
                    # skip extraction loop entirely
                else:
                    print("[WARN] feature cache size mismatch; rebuilding features")
            else:
                # checkpoint exists but resume not requested; leave for later saving
                pass
        except Exception as e:
            print("[WARN] Failed to load feature cache; rebuilding features:", e)
    crawl_cache: Dict[str, Any] = {}
    if use_page_features and crawl is not None:
        print("[INFO] use_page_features enabled: fetching pages via crawler (this may be slow)")
    # only run extraction loop if X_list not already populated from cache
    if not X_list:
        kept_idx: List[int] = []
        try:
            for idx, row in df.iterrows():
                u = str(row[url_col])
                page_feats = None
                if use_page_features:
                    page_feats = {}
                    for k in ("body_len", "num_anchors", "num_forms", "num_external_links",
                              "has_password_input", "num_scripts", "title_len", "suspicious_keyword_count"):
                        if k in row:
                            page_feats[k] = row[k]
                    has_page_cols = any(k in row for k in ("body_len", "num_anchors", "num_forms"))
                    if not has_page_cols:
                        # If parser columns not present in CSV, try crawling the URL to obtain page features
                        if crawl is not None:
                            try:
                                if u in crawl_cache:
                                    cr = crawl_cache[u]
                                else:
                                    cr = crawl(u)
                                    crawl_cache[u] = cr
                                if cr and isinstance(cr, object) and getattr(cr, "parsed", None):
                                    parsed = cr.parsed or {}
                                    pf = parsed.get("page_features") if isinstance(parsed, dict) else None
                                    if pf:
                                        page_feats = pf
                                    else:
                                        page_feats = None
                                else:
                                    page_feats = None
                                # progress log
                                if len(crawl_cache) and len(crawl_cache) % 500 == 0:
                                    print(f"[INFO] crawled {len(crawl_cache)} pages so far...")
                            except Exception:
                                page_feats = None
                        else:
                            page_feats = None

                try:
                    vec = extract_features(u, page_feats)
                except Exception:
                    misses += 1
                    continue
                if not vec:
                    misses += 1
                    continue
                X_list.append(vec)
                kept_idx.append(idx)
        except KeyboardInterrupt:
            print("\n[ABORTED] Interrupted by user during feature extraction. Saving partial cache...")
            try:
                # Attempt to align partial `y` with the features we extracted so far
                if kept_idx:
                    y_partial = df.loc[kept_idx, "label"].astype(int).values
                else:
                    y_partial = df.loc[df.index[: len(X_list)], "label"].astype(int).values

                X_np = np.asarray(X_list)
                y_np = np.asarray(y_partial)
                np.savez_compressed(cache_path, X=X_np, y=y_np)
                print(f"[INFO] Saved partial feature cache to {cache_path} ({len(X_list)} samples)")
            except Exception as e:
                print("[WARN] Failed to save partial cache on interrupt:", e)
            # Re-raise to allow outer handler (CLI) to exit with proper code
            raise

    # align y length to X_list built (if cache loaded earlier, y already set)
    if 'y' not in locals():
        if 'kept_idx' in locals() and kept_idx:
            y = df.loc[kept_idx, "label"].astype(int).values
        else:
            y = df.loc[df.index[:len(X_list)], "label"].astype(int).values

    print(f"Built feature vectors: {len(X_list)} (skipped {misses})")

    # persist feature cache so an interrupted run can resume quickly
    try:
        X_np = np.asarray(X_list)
        y_np = np.asarray(y)
        np.savez_compressed(cache_path, X=X_np, y=y_np)
        print(f"[INFO] Saved feature cache to {cache_path}")
    except Exception as e:
        print("[WARN] Failed to save feature cache:", e)
    # (y already aligned above)

    unique_labels = set(y.tolist())
    print("Label distribution before balancing:", pd.Series(y).value_counts().to_dict())
    if len(unique_labels) < 2:
        raise ValueError("Dataset only contains one class after cleaning. Provide both phishing and legit examples.")

    # optional balancing (undersample majority)
    if balance:
        try:
            temp_df = df.iloc[:len(X_list)].copy()
            temp_df["__feat_idx"] = range(len(X_list))
            counts = temp_df["label"].value_counts()
            min_count = int(counts.min())
            parts = []
            for lbl in counts.index:
                part = temp_df[temp_df["label"] == lbl].sample(n=min_count, random_state=42)
                parts.append(part)
            df_balanced = pd.concat(parts, ignore_index=True)
            X_list = [extract_features(str(df_balanced.loc[i, url_col]), None) for i in df_balanced.index]
            y = df_balanced["label"].astype(int).values
            print("Balanced dataset by undersampling. New distribution:", pd.Series(y).value_counts().to_dict())
        except Exception as e:
            print("Warning: balancing failed, continuing without balancing:", e)

    # train/test split
    stratify_arg = y if len(set(y)) > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X_list, y, test_size=test_size, random_state=42, stratify=stratify_arg
    )

    # model building
    base_rf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    model_to_save = base_rf
    if calibrate and CalibratedClassifierCV is not None:
        print("Using CalibratedClassifierCV for probability calibration")
        model_to_save = CalibratedClassifierCV(base_rf, cv=3)

    print("Fitting model...")
    model_to_save.fit(X_train, y_train)

    # evaluation
    try:
        y_pred = model_to_save.predict(X_test)
        print("=== EVALUATION (test split) ===")
        print(classification_report(y_test, y_pred, digits=3))
    except Exception:
        print("Evaluation skipped (maybe single-class or other error)")

    # save metadata and model
    y_counts = {int(k): int(v) for k, v in pd.Series(y).value_counts().to_dict().items()}
    feature_count = len(X_list[0]) if X_list else len(URL_FEATURE_NAMES)
    meta = _make_metadata(model_to_save, FEATURE_NAMES[:feature_count], (len(X_list), feature_count), y_counts)
    save_model_and_metadata(model_to_save, meta)

    print("[OK] Model trained successfully")
    print("[OK] Total samples used (after cleaning/balancing):", len(X_list))
    print("[OK] Model saved to:", MODEL_PATH)
    print("[OK] Metadata saved to:", META_PATH)


# ------------------ LOAD / PREDICT ------------------
def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Model belum dilatih. Jalankan: python -m src.cli train <dataset>")
    return joblib.load(MODEL_PATH)


def load_model_safe() -> Tuple[Optional[Any], Optional[str]]:
    """
    Try loading the model; return (model, metadata) or (None, error_message).
    Useful if the joblib is corrupted (EOF, numpy mismatch).
    """
    try:
        model = load_model()
        meta = None
        if META_PATH.exists():
            try:
                with open(META_PATH, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
            except Exception:
                meta = None
        return model, meta
    except Exception as e:
        logger.exception("Failed to load model: %s", e)
        return None, str(e)


def _proba_for_positive_class(model, proba_arr: List[float]) -> float:
    try:
        if hasattr(model, "classes_") and 1 in model.classes_:
            idx = list(model.classes_).index(1)
            return float(proba_arr[idx])
        return float(proba_arr[-1])
    except Exception:
        return float(proba_arr[-1])


def _ensure_feature_length(feats: List[float], model) -> List[float]:
    try:
        if hasattr(model, "n_features_in_"):
            expected = int(model.n_features_in_)
            if len(feats) < expected:
                return feats + [0.0] * (expected - len(feats))
            if len(feats) > expected:
                return feats[:expected]
    except Exception:
        pass
    return feats


def _heuristic_boost(url: str, current_proba: float) -> float:
    """
    Apply lightweight heuristic boosts for known suspicious patterns to reduce false negatives.
    This returns an increased probability (clamped to 0..1).
    """
    host = _extract_hostname(url) or ""
    host = host.lower()
    boost = 0.0
    # shorteners or free hosting -> boost modestly
    if any(s in host for s in SHORT_URL_SERVICES):
        boost += 0.20
    if any(pat in host for pat in SUSPECT_HOST_PATTERNS):
        boost += 0.25
    if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
        boost += 0.18
    # suspicious keyword in URL -> small boost
    low = url.lower()
    if any(k in low for k in SUSPICIOUS_KEYWORDS):
        boost += 0.10
    new = min(1.0, current_proba + boost)
    return new


def predict_url(url: str, page_features: Optional[Dict[str, Any]] = None,
                allow_feature_mismatch: bool = True,
                apply_heuristic_boost: bool = True) -> Tuple[int, float, int]:
    """
    Predict label for a URL.
    Returns (label:int, probability:float, confidence_percent:int)
    """
    model, meta_or_err = load_model_safe()
    if model is None:
        raise RuntimeError(f"Model not available: {meta_or_err}")

    feats = extract_features(url, page_features)

    expected = getattr(model, "n_features_in_", None)
    actual = len(feats)
    if expected is not None and expected != actual:
        if allow_feature_mismatch:
            feats = _ensure_feature_length(feats, model)
        else:
            raise RuntimeError(f"Feature mismatch: model expects {expected} features but got {actual}. Retrain or set allow_feature_mismatch=True")

    try:
        if hasattr(model, "predict_proba"):
            proba_arr = model.predict_proba([feats])[0]
            phishing_proba = _proba_for_positive_class(model, proba_arr)

            # small targeted boosts for patterns not well captured by RF features
            boost = 0.0
            host = _extract_hostname(url).lower()
            if host.endswith(("web.app", "weeblysite.com", "vercel.app", "netlify.app", "github.io")):
                boost += 0.15
            if any(k in url.lower() for k in ("login", "verify", "secure", "update")):
                boost += 0.10
            phishing_proba = min(1.0, phishing_proba + boost)
        else:
            pred = int(model.predict([feats])[0])
            phishing_proba = 1.0 if pred == 1 else 0.0

        if apply_heuristic_boost:
            phishing_proba = _heuristic_boost(url, float(phishing_proba))

        try:
            from . import config
            THRESH = float(getattr(config, "ML_DECISION_THRESHOLD", 0.35))
        except Exception:
            THRESH = 0.35

        label = 1 if phishing_proba >= THRESH else 0
        confidence = int(round(phishing_proba * 100))

        return int(label), float(phishing_proba), int(confidence)
    except Exception as e:
        raise RuntimeError(f"Prediction failed: {e}")


# ------------------ UTILITY: explain decision ------------------
def explain_decision(url: str, page_features: Optional[Dict[str, Any]] = None) -> dict:
    feats = extract_features(url, page_features)
    model, meta_or_err = load_model_safe()
    model_meta = meta_or_err if model is not None else {"load_error": meta_or_err}

    ml_label, ml_proba, ml_conf = (0, 0.0, 0)
    try:
        if model is not None:
            ml_label, ml_proba, ml_conf = predict_url(url, page_features=page_features, allow_feature_mismatch=True, apply_heuristic_boost=False)
    except Exception as e:
        model_meta = {"error": str(e)}

    return {
        "url": url,
        "features": dict(zip(FEATURE_NAMES[:len(feats)], feats)),
        "ml_label": int(ml_label),
        "ml_probability": float(ml_proba),
        "ml_confidence_percent": int(ml_conf),
        "model_meta": model_meta,
    }
