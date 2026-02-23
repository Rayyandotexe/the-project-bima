"""Scan CSV datasets and produce summary CSV + markdown table.

Usage: python scripts/dataset_stats.py

Creates: 'lampiran_dataset_stats.csv' in the repository root and prints a markdown table.

Comments are provided for each step as requested.
"""
from pathlib import Path
import pandas as pd
import json
import sys


def detect_label_column(df: pd.DataFrame):
    """Try to find a label column name in the dataframe.

    Strategy:
    - Prefer exact matches of common names.
    - Then prefer columns containing 'label' or 'class'.
    - Otherwise return None.
    """
    common = {"label", "class", "status", "target", "label_name", "is_phish", "phishing"}
    cols = list(df.columns)
    for c in cols:
        if c.lower() in common:
            return c
    for c in cols:
        lname = c.lower()
        if "label" in lname or "class" in lname or "target" in lname:
            return c
    return None


def map_label_counts(series: pd.Series):
    """Map a label series to phishing/legitimate counts using heuristics.

    Returns (phishing_count, legitimate_count).
    If unknown, return (None, None).
    """
    # Normalize to string for pattern checks
    s = series.dropna()
    if s.empty:
        return 0, 0

    # If numeric-like (only integers), treat 1 as phishing, 0 as legitimate when appropriate
    try:
        numeric = pd.to_numeric(s, errors="coerce")
        if not numeric.isna().any():
            uniq = set(numeric.unique())
            if uniq <= {0, 1}:
                phishing = int((numeric == 1).sum())
                legitimate = int((numeric == 0).sum())
                return phishing, legitimate
    except Exception:
        pass

    # Textual mapping: look for keywords
    text = s.astype(str).str.lower().str.strip()
    phishing_keywords = ["phish", "phishing", "malicious", "malware", "bad"]
    legitimate_keywords = ["legit", "legitimate", "benign", "good", "safe", "ham"]

    phishing_mask = text.str.contains("|".join(phishing_keywords), na=False)
    legitimate_mask = text.str.contains("|".join(legitimate_keywords), na=False)

    # Count matches
    phishing = int(phishing_mask.sum())
    legitimate = int(legitimate_mask.sum())

    # If none matched, try a fallback: if there are exactly two unique textual values,
    # assign the one containing 'phish' or 'malicious' as phishing if present.
    if phishing + legitimate == 0:
        uniq_vals = text.unique().tolist()
        if len(uniq_vals) == 2:
            a, b = uniq_vals
            a_phish = any(k in a for k in phishing_keywords)
            b_phish = any(k in b for k in phishing_keywords)
            if a_phish and not b_phish:
                phishing = int((text == a).sum())
                legitimate = int((text == b).sum())
            elif b_phish and not a_phish:
                phishing = int((text == b).sum())
                legitimate = int((text == a).sum())

    # If still zero for both, return None to indicate unknown mapping
    if phishing + legitimate == 0:
        return None, None
    return phishing, legitimate


def row_to_short_str(row: dict, max_len: int = 200):
    """Serialize a row dict to a short JSON-like string for CSV/markdown convenience."""
    s = json.dumps(row, ensure_ascii=False)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def main():
    # 1) Locate datasets directory
    datasets_dir = Path("datasets")
    if not datasets_dir.exists() or not datasets_dir.is_dir():
        print("Error: 'datasets/' directory not found.")
        sys.exit(1)

    # 2) Find all CSV files inside datasets/
    csv_files = sorted(datasets_dir.glob("*.csv"))
    if not csv_files:
        print("No CSV files found in 'datasets/'.")
        sys.exit(0)

    results = []

    # 3) Iterate files and collect stats
    for p in csv_files:
        # Read CSV with a tolerant configuration
        try:
            df = pd.read_csv(p, low_memory=False, on_bad_lines="skip")
        except Exception as e:
            # If read fails, record the error and continue
            results.append({
                "filename": str(p.name),
                "total_rows": None,
                "phishing_count": None,
                "legitimate_count": None,
                "sample_rows": json.dumps({"error": str(e)}),
            })
            continue

        total_rows = int(len(df))

        # Detect label column and map counts
        label_col = detect_label_column(df)
        phishing_count = None
        legitimate_count = None
        if label_col is not None:
            phishing_count, legitimate_count = map_label_counts(df[label_col])

        # Get up to 5 sample rows (as short JSON strings)
        samples = [row_to_short_str(r) for r in df.head(5).to_dict(orient="records")]

        results.append(
            {
                "filename": str(p.name),
                "total_rows": total_rows,
                "label_column": label_col,
                "phishing_count": phishing_count,
                "legitimate_count": legitimate_count,
                "sample_rows": json.dumps(samples, ensure_ascii=False),
            }
        )

    # 4) Save results to 'lampiran_dataset_stats.csv' in repo root
    out_path = Path("lampiran_dataset_stats.csv")
    out_df = pd.DataFrame(results)
    out_df.to_csv(out_path, index=False)

    # 5) Print a simple markdown table to stdout for quick viewing
    # Build header
    md_lines = []
    md_lines.append("| filename | rows | label_col | phishing | legitimate | sample_preview |")
    md_lines.append("|---|---:|---|---:|---:|---|")
    for r in results:
        sample_preview = json.loads(r.get("sample_rows", "[]"))
        sample_preview = sample_preview[0] if sample_preview else ""
        phishing = r.get("phishing_count")
        legitimate = r.get("legitimate_count")
        md_lines.append(
            "| {} | {} | {} | {} | {} | {} |".format(
                r.get("filename", ""),
                r.get("total_rows", ""),
                r.get("label_column", ""),
                phishing if phishing is not None else "unknown",
                legitimate if legitimate is not None else "unknown",
                sample_preview.replace("\n", " ") if isinstance(sample_preview, str) else str(sample_preview),
            )
        )

    print("\n".join(md_lines))
    print(f"\nSaved summary to: {out_path}")


if __name__ == "__main__":
    main()
