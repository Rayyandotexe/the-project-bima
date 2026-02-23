import pandas as pd
from pathlib import Path

d = Path("datasets")

for f in ["URL_dataset.csv", "Phishing_URLs.csv"]:
    p = d / f
    if not p.exists():
        print("File not found:", p)
        continue

    df = pd.read_csv(p)

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
