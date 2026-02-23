import pandas as pd
from .validator import validate_url, normalize_record
from .storage import save_record


def ingest_csv(path, source_label="feed"):
    df = pd.read_csv(path)
    for _, row in df.iterrows():
        url = row.get("URL") or row.get("url") or row.get("link")
        if not validate_url(url):
            continue
        rec = {
            "url": url,
            "category": row.get("type", "phishing"),
            "source": source_label,
            }
        n = normalize_record(rec)
        save_record(n)