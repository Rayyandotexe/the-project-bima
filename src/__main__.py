from .ingest import ingest_csv
from .storage import init_db


if __name__ == "__main__":
    init_db()
    ingest_csv("data/URL_dataset.csv", source_label="feed")
    print("Done ingesting.")