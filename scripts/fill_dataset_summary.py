"""Fill lampiran_b_dataset_summary.csv with label counts and modification dates.

Usage: python scripts/fill_dataset_summary.py

Creates: 'lampiran_b_dataset_summary_filled.csv' in repo root.

The script reads the summary CSV, scans all CSV files in 'datasets/',
detects label columns with priority ['type','label','class'], counts phishing
and legitimate labels, sets 'date_collected' from file modification time,
and writes a new CSV without changing column order.
"""
from pathlib import Path
from datetime import datetime
import pandas as pd
import sys
import re
import argparse


def detect_label_column_priority(df: pd.DataFrame):
    """Detect label column using priority list, fallback to name-contains.

    Priority: 'type', 'label', 'class' (case-insensitive).
    If none match exactly, fall back to first column containing 'label' or 'class'.
    Returns column name or None.
    """
    priority = ["type", "label", "class"]
    cols = list(df.columns)
    lower_map = {c.lower(): c for c in cols}
    for p in priority:
        if p in lower_map:
            return lower_map[p]
    # fallback: contains
    for c in cols:
        ln = c.lower()
        if "label" in ln or "class" in ln:
            return c
    return None


def count_labels(series: pd.Series):
    """Count phishing and legitimate labels from a series (case-insensitive).

    phishing: matches 'phishing', 'phish', 'bad', 'malicious'
    legitimate: matches 'benign', 'legitimate', 'good', 'normal'

    Returns (phishing_count:int, legitimate_count:int).
    """
    if series is None:
        return None, None

    # Convert to string, lowercase, and handle NaN safely
    s = series.astype(str).fillna("").str.lower().str.strip()

    # Compile regex for word-boundary matching of target keywords
    phishing_re = re.compile(r"\b(phishing|phish|bad|malicious)\b", flags=re.IGNORECASE)
    legitimate_re = re.compile(r"\b(benign|legitimate|good|normal)\b", flags=re.IGNORECASE)

    # Use Series.str.contains with regex patterns; protect against empty strings
    phishing_mask = s.str.contains(phishing_re, na=False)
    legitimate_mask = s.str.contains(legitimate_re, na=False)

    phishing_count = int(phishing_mask.sum())
    legitimate_count = int(legitimate_mask.sum())

    return phishing_count, legitimate_count


def main():
    # Parse optional CLI arguments for summary path and output
    parser = argparse.ArgumentParser(description="Fill dataset summary with label counts and dates")
    parser.add_argument("--summary", "-s", help="Path to summary CSV (default tries lampiran_b_dataset_summary.csv then lampiran_dataset_stats.csv)")
    parser.add_argument("--out", "-o", help="Output CSV path", default="lampiran_b_dataset_summary_filled.csv")
    args = parser.parse_args()

    # Paths for summary and datasets dir
    repo_root = Path(".").resolve()
    datasets_dir = repo_root / "datasets"

    # Determine summary input path: CLI arg > lampiran_b_dataset_summary.csv > lampiran_dataset_stats.csv
    if args.summary:
        summary_path = Path(args.summary)
        if not summary_path.is_absolute():
            summary_path = repo_root / summary_path
    else:
        candidate_a = repo_root / "lampiran_b_dataset_summary.csv"
        candidate_b = repo_root / "lampiran_dataset_stats.csv"
        if candidate_a.exists():
            summary_path = candidate_a
        else:
            summary_path = candidate_b

    # Exit if summary file not found
    if not summary_path.exists():
        print(f"Error: '{summary_path}' not found.")
        sys.exit(1)

    # Read existing summary into DataFrame while preserving columns/order
    summary_df = pd.read_csv(summary_path)

    # Ensure expected columns exist; do not modify structure if columns missing
    required_cols = ["filename", "total_rows", "label_column", "phishing_count", "legitimate_count", "date_collected", "sample_rows_path"]
    for c in required_cols:
        if c not in summary_df.columns:
            print(f"Warning: expected column '{c}' not in summary; continuing without it.")

    # Map filenames to their row indices for quick updates
    if "filename" in summary_df.columns:
        filename_to_idx = {str(r[1]["filename"]): r[0] for r in summary_df.iterrows()}
    else:
        filename_to_idx = {}

    # Scan dataset CSV files
    if not datasets_dir.exists() or not datasets_dir.is_dir():
        print("Error: 'datasets/' directory not found.")
        sys.exit(1)

    csv_files = sorted(datasets_dir.glob("*.csv"))
    if not csv_files:
        print("No CSV files found in 'datasets/'. Nothing to do.")
        sys.exit(0)

    # Iterate each dataset CSV and compute counts and modification date
    for p in csv_files:
        fname = p.name

        # Read file safely; skip bad lines if necessary
        try:
            df = pd.read_csv(p, low_memory=False, on_bad_lines="skip")
        except Exception as e:
            print(f"Warning: failed reading {fname}: {e}")
            continue

        # Detect label column with priority and fallback
        label_col = detect_label_column_priority(df)

        # If label column found, count labels; otherwise leave counts as None
        if label_col is not None:
            phishing_count, legitimate_count = count_labels(df[label_col])
        else:
            phishing_count, legitimate_count = None, None

        # Get file modification date in YYYY-MM-DD
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime).date().isoformat()
        except Exception:
            mtime = None

        # Update the corresponding row(s) in summary_df matching filename
        if fname in filename_to_idx:
            idx = filename_to_idx[fname]
            # Only assign to existing columns to avoid changing structure
            if "label_column" in summary_df.columns:
                summary_df.at[idx, "label_column"] = label_col
            if "phishing_count" in summary_df.columns:
                # Use empty value (NaN) if None to keep CSV clean
                summary_df.at[idx, "phishing_count"] = phishing_count
            if "legitimate_count" in summary_df.columns:
                summary_df.at[idx, "legitimate_count"] = legitimate_count
            if "date_collected" in summary_df.columns:
                summary_df.at[idx, "date_collected"] = mtime
        else:
            # If there's no matching row in summary, report and skip
            print(f"Note: '{fname}' not present in summary CSV; skipping update for this file.")

    # Write filled summary to new file without changing column order
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = repo_root / out_path
    summary_df.to_csv(out_path, index=False)
    print(f"Saved filled summary to: {out_path}")


if __name__ == "__main__":
    main()
