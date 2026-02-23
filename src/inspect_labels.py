import pandas as pd
from pathlib import Path

d = Path("datasets")

csvs = sorted(d.glob("*.csv"))
if not csvs:
    print("No CSV files found in datasets/")
    raise SystemExit(1)

for p in csvs:
    try:
        df = pd.read_csv(p, dtype=str, low_memory=False)
    except Exception as e:
        print(f"[WARN] Failed to read {p}: {e}")
        continue

    print("\n===", p.name, "rows:", len(df))
    print("columns:", df.columns.tolist())

    col = next((c for c in df.columns if c.lower() in ("type", "label", "class")), None)
    print("detected label col:", col)

    if col:
        print("label values:")
        print(
            df[col]
            .astype(str)
            .str.strip()
            .str.lower()
            .value_counts(dropna=False)
            .head(20)
        )
