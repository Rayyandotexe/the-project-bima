from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Text

Base = declarative_base()

class Record(Base):
    __tablename__ = "records"

    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, index=True)
    discovered = Column(String)
    category = Column(String)
    source = Column(String)
    status = Column(Integer)
    resolved = Column(Integer)
    confidence_level = Column(Integer)
    brand = Column(String)
    screenshots = Column(Text)
    meta = Column(Text)
