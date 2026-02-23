# src/evaluate_dataset.py
import sys
import pandas as pd
from pathlib import Path
from src.model import extract_features, predict_url, _normalize_label_col
from src.model import load_model_safe

def evaluate(csv_path):
    df = pd.read_csv(csv_path)
    col = next((c for c in df.columns if c.lower() in ("type","label","class")), None)
    urlcol = next((c for c in df.columns if c.lower() in ("url","link","location")), None)
    if not col or not urlcol:
        print("Missing columns")
        return
    df = df.dropna(subset=[urlcol])
    df['label_norm'] = _normalize_label_col(df[col])
    df = df.dropna(subset=['label_norm'])
    y_true = df['label_norm'].astype(int).tolist()
    y_pred = []
    false_negatives = []
    for i, row in df.iterrows():
        url = row[urlcol]
        try:
            lbl, proba, conf = predict_url(url)
        except Exception as e:
            lbl, proba, conf = 0, 0.0, 0
        y_pred.append(lbl)
        if int(row['label_norm']) == 1 and lbl == 0:
            false_negatives.append((url, proba, conf))
    from sklearn.metrics import confusion_matrix, classification_report
    print(confusion_matrix(y_true, y_pred))
    print(classification_report(y_true, y_pred, digits=4))
    print("\nSample false negatives (phishing labeled as legit):")
    for u, p, c in false_negatives[:50]:
        print(u, p, c)
    print(f"\nTotal false negatives: {len(false_negatives)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m src.evaluate_dataset datasets/Phishing_URLs.csv")
    else:
        evaluate(sys.argv[1])
