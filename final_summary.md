# Final Summary — The-Project-Bima

Dokumen ini menjelaskan secara menyeluruh arsitektur, alur data, modul utama, detail implementasi teknis, dan langkah reproduksi untuk proyek `the-project-bima`.

1) Tujuan proyek
- Mendeteksi URL phishing menggunakan pendekatan hybrid: kombinasi rules deterministic (heuristik) dan model machine learning berbasis fitur URL + fitur halaman.

2) Arsitektur & alur data
- Ingest: CSV dataset ditempatkan di `datasets/` dan dapat digabung menggunakan `src/merge_dataset.py` atau `src/ingest.py`.
- Crawler/Fetcher: `src/crawler.py` dan `src/fetcher.py` mengambil halaman (opsional screenshot via `src/screenshots.py`) lalu mem-parsing HTML.
- Parser & page features: `src/parser.py` mengekstrak struktur halaman (anchors, forms, scripts, body_snippet) dan fungsi `extract_page_features` menghasilkan fitur numeric/boolean halaman.
- URL features: `src/features.py` (atau `src.model.extract_features`) mengekstrak fitur URL (length, entropy, token counts, suspicious TLDs, brand tokens, dll.).
- Rules engine: `src/rules_engine.py` diterapkan pada hasil parsed page untuk menghasilkan `rules_score` dan `rules_label`.
- Model: `src/model.py` memproses dataset, mengekstrak fitur (menggunakan checkpoint `datasets/feature_cache.npz` jika ada), melatih RandomForest (default n_estimators=200) dan menyimpan artefak `src/trained_model.pkl` dan `src/trained_model_meta.json`.
- Orkestrasi/pipeline: `src/classifier.py` memanggil crawler → rules → ML (fallback/hybrid) dan memutuskan label akhir.
- Antarmuka: `src/cli.py` (perintah `test` dan `train`) dan `src/web.py` (API Flask bila dijalankan).

3) Modul utama (ringkasan cepat)
- `src/features.py`: fungsi `extract_url_features(url)` dan `extract_url_features_dict(url)` — output: vektor fitur terurut (15 fitur URL). Lokasi integrasi: `src/model.extract_features` dapat menggunakan module ini.
- `src/parser.py`: parsing HTML, `parse_html` + `extract_page_features` menghasilkan page-level features (body_len, num_anchors, num_forms, dll.). Dipakai oleh crawler dan model ketika `--use-crawler`.
- `src/rules_engine.py`: rules deterministic (blacklist, anchor mismatch, suspicious keywords). Dipanggil dari crawler/classifier.
- `src/crawler.py`: mengambil halaman, mengumpulkan parsed HTML, menjalankan rules, menangkap screenshot (opsional) → mengembalikan `CrawlResult`.
- `src/model.py`: menyiapkan data, ekstraksi fitur gabungan, balancing, train_test_split, melatih RandomForest, menyimpan model & metadata, fungsi `predict_url`, `explain_decision`.
- `src/classifier.py`: fungsi `classify_url(url, capture_screenshot=False)` menggabungkan hasil rules & ML menjadi keputusan hybrid.
- `src/cli.py`: CLI untuk `train` dan `test`; menghasilkan screenshot ke `bima_screenshot.png` saat `--screenshot`.

4) Fitur yang diekstraksi (ringkasan)
- URL features (15): `url_length`, `hostname_length`, `num_dots`, `num_hyphens`, `num_subdirs`, `has_ip`, `has_at_symbol`, `has_https`, `suspicious_keyword_count`, `url_entropy`, `hostname_entropy`, `free_host_service`, `suspicious_tld`, `numeric_chars_in_host`, `brand_token_present`.
- Page features (contoh): `body_len`, `num_anchors`, `num_forms`, `num_external_links`, `has_password_input`, `num_scripts`, `title_len`, `suspicious_keyword_count (page)`, `forms_with_password`, `external_link_ratio`, `redirect_count`.

5) Artefak model & metadata
- `src/trained_model.pkl`: model serialisasi (joblib). Ada di repo `src/`.
- `src/trained_model_meta.json`: metadata dibuat saat training (termasuk `feature_names`, `X_shape`, `label_counts`), contoh isi sudah ada (lihat `created_at`, versi python/sklearn, `feature_names`).
- Catatan: metadata saat ini tidak menyimpan hyperparameters training lengkap atau metrics numerik; classification_report hanya dicetak ke stdout selama training.

6) Cara reproduksi training dan evaluasi (perintah siap pakai)
- Setup venv & install:
```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
- Train (auto-detect datasets/):
```
python -m src.cli train --force --checkpoint datasets/feature_cache.npz --resume
```
Simpan stdout ke file:
```
python -m src.cli train --force --checkpoint datasets/feature_cache.npz --resume 2>&1 | tee training_log.txt
```
- Evaluasi pada CSV berlabel:
```
python -m src.evaluate_dataset datasets/Phishing_URLs.csv > classification_report.txt
```
- Ekstrak false positives/negatives:
```
python - <<'PY'
from src.model import predict_url, _normalize_label_col
import pandas as pd
df=pd.read_csv('datasets/Phishing_URLs.csv')
col=next((c for c in df.columns if c.lower() in ('type','label','class')),None)
urlc=next((c for c in df.columns if c.lower() in ('url','link','location')),None)
df=df.dropna(subset=[urlc])
df['label_norm']=_normalize_label_col(df[col])
df=df.dropna(subset=['label_norm'])
false_neg=[]
false_pos=[]
for _,r in df.iterrows():
    u=r[urlc]
    lbl,proba,conf=predict_url(u)
    if int(r['label_norm'])==1 and lbl==0:
        false_neg.append({'url':u,'proba':proba,'conf':conf})
    if int(r['label_norm'])==0 and lbl==1:
        false_pos.append({'url':u,'proba':proba,'conf':conf})
import json
open('false_cases.json','w').write(json.dumps({'false_neg':false_neg[:50],'false_pos':false_pos[:50]},indent=2))
PY
```

7) Produksi laporan evaluasi (plots)
- Buat `scripts/plot_eval.py` yang memanggil proses evaluasi, mengumpulkan y_true/y_pred, lalu menyimpan `confusion_matrix.png`, `roc_auc.png` dan `classification_report.txt`. Contoh perintah:
```
python scripts/plot_eval.py datasets/Phishing_URLs.csv --out-dir assets/eval/
```

8) Daftar file penting & di mana mencari bukti
- `export_sample.csv` — contoh record (head tersedia).
- `src/trained_model_meta.json` — metadata model.
- `src/trained_model.pkl` — model joblib.
- `training_log.txt` — simpan stdout training (tidak otomatis dibuat).
- `classification_report.txt` — hasil evaluasi pada dataset terpisah (gunakan evaluate_dataset).
- `false_cases.json` — contoh false pos/neg (buat dengan snippet di atas).
- `assets/sample_screenshots/` — simpan screenshot evidence per minggu.

9) Rekomendasi untuk laporan final
- Sertakan: `src/trained_model_meta.json`, `src/trained_model.pkl`, `training_log.txt`, `classification_report.txt`, `false_cases.json`, dan screenshots (`assets/sample_screenshots/`).
- Jika ingin metrik lengkap tersimpan otomatis, tambahkan sedikit perubahan di `src/model.py` sebelum `save_model_and_metadata` untuk menyimpan `classification_report` dan hyperparameters ke `meta`.

10) Next steps opsional
- Tambahkan script `scripts/record_training.py` untuk menyimpan hyperparams + metrics ke metadata.
- Tambahkan CI workflow untuk menjalankan `pytest` dan menghasilkan artefak evaluasi otomatis.

---

File ini dibuat otomatis oleh tooling pendamping. Jika Anda ingin saya menambahkan diagram arsitektur atau contoh output training yang diformat ke dalam `assets/` atau `docs/`, beri tahu saya dan saya akan membuat file tambahan.
