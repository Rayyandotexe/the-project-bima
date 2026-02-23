from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base, Record   # ← INI WAJIB ADA

engine = create_engine("sqlite:///bima.db")
Session = sessionmaker(bind=engine)


def init_db():
    Base.metadata.create_all(engine)

def get_record_by_url(url: str):
    session = Session()
    try:
        return session.query(Record).filter(Record.url == url).one_or_none()
    finally:
        session.close()


def save_record(rec: dict):
    session = Session()
    try:
        url_val = rec["url"]

        existing = session.query(Record).filter(Record.url == url_val).one_or_none()

        category_val = (
            ",".join(rec["category"])
            if isinstance(rec.get("category"), list)
            else rec.get("category")
        )

        screenshots_val = rec.get("screenshots")
        meta_val = rec.get("metadata")

        if existing:
            existing.discovered = rec.get("discovered", existing.discovered)
            existing.category = category_val or existing.category
            existing.source = rec.get("source", existing.source)
            existing.status = rec.get("status", existing.status)
            existing.resolved = rec.get("resolved", existing.resolved)
            existing.confidence_level = rec.get("confidence_level", existing.confidence_level)
            existing.brand = rec.get("brand", existing.brand)
            existing.screenshots = screenshots_val or existing.screenshots
            existing.meta = meta_val or existing.meta
            session.commit()
            return existing
        else:
            r = Record(
                url=url_val,
                discovered=rec.get("discovered"),
                category=category_val,
                source=rec.get("source"),
                status=rec.get("status", 0),
                resolved=rec.get("resolved", 0),
                confidence_level=rec.get("confidence_level", 0),
                brand=rec.get("brand", "-"),
                screenshots=screenshots_val,
                meta=meta_val,
            )
            session.add(r)
            session.commit()
            return r
    finally:
        session.close()
