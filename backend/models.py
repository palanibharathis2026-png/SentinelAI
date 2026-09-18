"""Database tables."""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    department: Mapped[str] = mapped_column(String(60))
    role: Mapped[str] = mapped_column(String(80))
    home_city: Mapped[str] = mapped_column(String(60))
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | blocked
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Event(Base):
    """One login session plus the activity performed in it, with its risk verdict."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("employees.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)

    city: Mapped[str] = mapped_column(String(60))
    country: Mapped[str] = mapped_column(String(60))
    lat: Mapped[float] = mapped_column(Float)
    lon: Mapped[float] = mapped_column(Float)
    ip: Mapped[str] = mapped_column(String(45))
    os: Mapped[str] = mapped_column(String(40))
    browser: Mapped[str] = mapped_column(String(40))
    failed_attempts: Mapped[int] = mapped_column(Integer)
    files_downloaded: Mapped[int] = mapped_column(Integer)
    mb_downloaded: Mapped[float] = mapped_column(Float)
    api_calls: Mapped[int] = mapped_column(Integer)
    sensitive_access: Mapped[int] = mapped_column(Integer)
    session_minutes: Mapped[int] = mapped_column(Integer)

    source: Mapped[str] = mapped_column(String(16))  # history | live | simulated
    scenario: Mapped[str | None] = mapped_column(String(40), nullable=True)  # ground truth, None = normal

    ml_score: Mapped[float] = mapped_column(Float)
    rule_score: Mapped[float] = mapped_column(Float)
    risk: Mapped[int] = mapped_column(Integer, index=True)
    tier: Mapped[str] = mapped_column(String(10), index=True)
    action: Mapped[str] = mapped_column(String(60))
    threat: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reasons: Mapped[list] = mapped_column(JSON)
    features: Mapped[dict] = mapped_column(JSON)

    status: Mapped[str] = mapped_column(String(16), default="open")  # open | resolved | false_positive
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation_source: Mapped[str | None] = mapped_column(String(16), nullable=True)
