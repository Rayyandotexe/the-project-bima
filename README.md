# the-project-bima

> Lightweight phishing/URL classification toolkit — pipeline for ingestion,
> parsing, feature extraction, rule-based checks and ML model training.

## Fitur

- Deteksi phishing berbasis fitur URL dan rules hybrid (deterministic + ML)
- Pipeline end-to-end: crawler/fetcher → parser → fitur → model → CLI/web
- Alat pengujian: unit & integration tests di `tests/`
- Artefak model dan metadata disimpan di `trained_model_meta.json`

## Struktur singkat repo

- `src/` – kode utama (parser, fitur, model, CLI, web)
- `datasets/` – CSV dataset mentah dan file sample
- `assets/` – screenshot dan materi pendukung
- `tests/` – test unit & integrasi
- `requirements.txt` – dependensi Python

## Instalasi (Windows)

1. Buat virtual environment dan aktifkan:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Install dependensi:

```powershell
pip install -r requirements.txt
```

## Quickstart

- Jalankan help CLI untuk melihat perintah yang tersedia:

```powershell
python -m src.cli --help
```

- Contoh training (seperti yang digunakan selama pengembangan):

```powershell
python -m src.cli train --use-crawler --checkpoint datasets/feature_cache.npz --resume
```

- Jalankan test suite:

```powershell
pytest -q
```

## Data

Letakkan dataset CSV di folder `datasets/`. Ada beberapa file sample seperti
`URL_dataset.csv` dan `Phishing_URLs.csv`. Sebelum training, jalankan skrip
pembersihan/merge bila perlu (`src/merge_dataset.py` / `src/ingest.py`).

## Penggunaan (skema umum)

1. Ingest/crawl dataset (`src/crawler.py`, `src/fetcher.py`).
2. Parse URL → ekstrak fitur (`src/parser.py`, `src/features.py`).
3. Terapkan rules awal (`src/rules_engine.py`).
4. Latih model pada fitur yang dihasilkan (`src/model.py`, `src/models.py`).
5. Gunakan CLI/web untuk inferensi (`src/cli.py`, `src/web.py`).

## Dokumentasi & lampiran

Screenshot & artifacts ditempatkan di `assets/sample_screenshots/`.
Logbook mingguan (jika tersedia) simpan di root atau `docs/`.

## Kontribusi

Silakan buka issue atau buat PR. Ikuti gaya commit dan tambahkan test untuk
perubahan fungsional.

## Lisensi

Tentukan lisensi proyek di sini (mis. MIT) atau tambahkan file `LICENSE`.
