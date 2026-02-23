#  src/db.py
import csv
from .storage import engine, Session, Record, init_db
from sqlalchemy import select

def ensure_db():
    """Create tables if not exists"""
    init_db()

def query_all(limit: int = 100):
    s = Session()
    try:
        q = s.query(Record).limit(limit)
        return q.all()
    finally:
        s.close()

def export_csv(path: str, limit: int = 1000):
    rows = query_all(limit=limit)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        header = ["id","url","discovered","category","source","status","resolved","confidence_level","brand","screenshots"]
        w.writerow(header)
        for r in rows:
            w.writerow([r.id, r.url, r.discovered, r.category, r.source, r.status, r.resolved, r.confidence_level, r.brand, r.screenshots])

if __name__ == "__main__":
    ensure_db()
    print("DB ready. Sample rows:")
    for rec in query_all(10):
        print(rec.id, rec.url, rec.confidence_level)
