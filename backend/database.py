"""Database connection. PostgreSQL in Docker, SQLite for quick local runs."""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinel.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    import models  # noqa: F401  (registers the tables)

    Base.metadata.create_all(engine)


# Kept across a demo reset: the admin's authenticator link and the audit trail.
KEEP_ON_RESET = {"settings", "audit_log"}


def reset_db() -> None:
    import models  # noqa: F401

    tables = [t for t in Base.metadata.sorted_tables if t.name not in KEEP_ON_RESET]
    Base.metadata.drop_all(engine, tables=tables)
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
