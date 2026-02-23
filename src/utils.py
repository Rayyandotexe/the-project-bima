# src/utils.py
import numpy as np
from pathlib import Path

def sanitize_for_json(obj):
    """
    Convert non-JSON-serializable objects into safe Python types
    """
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [sanitize_for_json(v) for v in obj]

    if isinstance(obj, tuple):
        return [sanitize_for_json(v) for v in obj]

    if isinstance(obj, np.generic):
        return obj.item()

    if isinstance(obj, Path):
        return str(obj)

    return obj

def hybrid_confidence(ml_score, rules_score):
    combined = 0.6 * ml_score + 0.4 * rules_score
    return int(max(0, min(100, round(combined * 100))))