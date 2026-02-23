import pandas as pd
from pathlib import Path

d = Path("datasets")

df1 = pd.read_csv(d / "URL_dataset.csv")
df2 = pd.read_csv(d / "Phishing_URLs.csv")

# normalisasi label
def normalize_label(x):
    x = str(x).strip().lower()
    if x == "phishing":
        return "phishing"
    if x == "legitimate":
        return "legitimate"
    return None

df1["type"] = df1["type"].apply(normalize_label)
df2["type"] = df2["type"].apply(normalize_label)

# gabungkan
df = pd.concat([df1, df2], ignore_index=True)

# hapus label invalid & duplikat URL
df = df.dropna(subset=["type"])
df = df.drop_duplicates(subset=["url"])

print("Final dataset:")
print(df["type"].value_counts())

df.to_csv(d / "TRAINING_dataset.csv", index=False)
