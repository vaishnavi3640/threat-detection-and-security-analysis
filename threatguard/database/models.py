"""
Database models for THREATGUARD using SQLAlchemy ORM.
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text,
    ForeignKey, Boolean, create_engine
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    websites = relationship("Website", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User id={self.id} username={self.username}>"


class Website(Base):
    __tablename__ = "websites"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    website_url = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="websites")
    scans = relationship("Scan", back_populates="website", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Website id={self.id} url={self.website_url}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    website_id = Column(Integer, ForeignKey("websites.id"), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow)
    security_score = Column(Float, default=0.0)
    privacy_score = Column(Float, default=0.0)
    trust_score = Column(Float, default=0.0)
    scan_status = Column(String(20), default="pending")  # pending, running, completed, failed
    scan_duration = Column(Float, default=0.0)           # seconds
    total_findings = Column(Integer, default=0)

    website = relationship("Website", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan id={self.id} status={self.scan_status} sec={self.security_score}>"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    finding_name = Column(String(256), nullable=False)
    category = Column(String(80), nullable=False)       # security / privacy
    severity = Column(String(20), nullable=False)        # Critical / High / Medium / Low / Informational
    confidence = Column(String(20), nullable=False)      # High / Medium / Low
    evidence = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding id={self.id} name={self.finding_name} sev={self.severity}>"


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    report_path = Column(String(512), nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="reports")

    def __repr__(self):
        return f"<Report id={self.id} scan_id={self.scan_id}>"
