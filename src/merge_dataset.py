import pandas as pd
from pathlib import Path

d = Path("datasets")

# Find all CSV files in datasets/ and concatenate them.
csvs = sorted(d.glob("*.csv"))
if not csvs:
    print("No CSV files found in datasets/ - nothing to merge.")
    raise SystemExit(1)

def normalize_label(x):
    x = str(x).strip().lower()
    if x == "phishing":
        return "phishing"
    if x == "legitimate":
        return "legitimate"
    return None

dfs = []
for p in csvs:
    try:
        df = pd.read_csv(p, dtype=str, low_memory=False)
    except Exception as e:
        print(f"[WARN] Failed to read {p}: {e}")
        continue
    # normalize column names to lowercase to be robust
    df.columns = [c.lower() for c in df.columns]
    # if no explicit type/label column but filename suggests phishing-only feed,
    # mark all rows as phishing
    if "type" not in df.columns:
        name = p.name.lower()
        if "phish" in name or name.startswith("phishing"):
            df["type"] = "phishing"
    # apply normalization if column exists
    if "type" in df.columns:
        df["type"] = df["type"].apply(normalize_label)
    dfs.append(df)

if not dfs:
    print("No readable CSV files found in datasets/")
    raise SystemExit(1)

df = pd.concat(dfs, ignore_index=True)

# drop invalid labels and duplicate URLs
if "type" in df.columns:
    df = df.dropna(subset=["type"])
else:
    print("No label column detected in merged dataset; output will include all rows")

if "url" in df.columns:
    df = df.drop_duplicates(subset=["url"])

print("Final dataset:")
if "type" in df.columns:
    print(df["type"].value_counts())
else:
    print(f"rows={len(df)} (no type column)")

df.to_csv(d / "TRAINING_dataset.csv", index=False)
