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
    resources: Mapped[list] = mapped_column(JSON, default=list)  # sensitive systems opened
    actions: Mapped[list] = mapped_column(JSON, default=list)  # privileged actions performed

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


class StaffAccess(Base):
    """Staff portal settings the admin controls: contact email and which systems a person may open."""

    __tablename__ = "staff_access"

    user_id: Mapped[str] = mapped_column(ForeignKey("employees.id"), primary_key=True)
    email: Mapped[str | None] = mapped_column(String(120), nullable=True)
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    known_emails: Mapped[list] = mapped_column(JSON, default=list)  # addresses this person has really used
    known_devices: Mapped[list] = mapped_column(JSON, default=list)  # devices enrolled by passing the email code


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("employees.id"), index=True)
    resource: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | approved | denied


class MailMessage(Base):
    """Every email SentinelAI sends (or would send, when SMTP is not configured)."""

    __tablename__ = "mail_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    to: Mapped[str] = mapped_column(String(120))
    subject: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(24))  # otp | login | first_access | denied | request | alert
    user_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    delivery: Mapped[str] = mapped_column(String(16), default="demo")  # sent | demo | failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    """Who did what: every sign-in and every security decision, for accountability."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime, index=True)
    actor: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(40))
    target: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class IntegrationLog(Base):
    """Every alert pushed to an outside channel (Slack, Teams, SMS, WhatsApp, webhook, SIEM) and every test."""

    __tablename__ = "integration_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime, index=True)
    channel: Mapped[str] = mapped_column(String(20))
    event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(12))  # sent | failed | received
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class StaffAccount(Base):
    """Staff portal logins created from the dashboard (the demo accounts live in auth.py)."""

    __tablename__ = "staff_accounts"

    username: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("employees.id"), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime)
