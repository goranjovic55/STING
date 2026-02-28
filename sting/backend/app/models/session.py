# STING 2.0 - Database Models
from sqlalchemy import Column, String, Integer, DateTime, JSON, Text, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, declarative_base
import enum

Base = declarative_base()


class SessionState(str, enum.Enum):
    HOSTILE = "hostile"
    PENDING = "pending"
    CLEARED = "cleared"
    NUKE_COMMITTED = "nuke_committed"
    LAB_TRANSFERRED = "lab_transferred"


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True)
    ip_address = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(20), nullable=False)  # ssh, http, ftp, etc
    score = Column(Integer, default=100)
    state = Column(SQLEnum(SessionState), default=SessionState.HOSTILE)
    resource_disk_mb = Column(Integer, default=0)
    resource_memory_mb = Column(Integer, default=0)
    resource_files = Column(Integer, default=0)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    ttl_expires_at = Column(DateTime, nullable=True)

    # Relationships
    events = relationship("Event", back_populates="session")
    writes = relationship("SessionWrite", back_populates="session")
    captures = relationship("Sample", back_populates="session")


class SessionWrite(Base):
    __tablename__ = "session_writes"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey("sessions.id"))
    path = Column(Text, nullable=False)
    content = Column(JSON, nullable=True)  # For file: content; for DB: query
    write_type = Column(String(20), nullable=False)  # file, db, http, etc
    created_at = Column(DateTime, server_default=func.now())

    session = relationship(Session, back_populates="writes")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey("sessions.id"))
    event_type = Column(String(50), nullable=False)  # CANARY_HIT, AUTH, COMMAND, etc
    payload = Column(JSON, nullable=True)
    score_delta = Column(Integer, default=0)
    created_at = Column(DateTime, server_default=func.now())

    session = relationship(Session, back_populates="events")


class Canary(Base):
    __tablename__ = "canaries"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    canary_type = Column(String(50), nullable=False)  # file, credential, url, dns, token
    path = Column(Text, nullable=True)  # For file canaries
    content = Column(Text, nullable=True)  # Content that triggers
    hit_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())


class Sample(Base):
    __tablename__ = "samples"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=True)
    sha256 = Column(String(64), unique=True, nullable=False)
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_type = Column(String(50), nullable=True)
    source_ip = Column(String(45), nullable=True)
    captured_at = Column(DateTime, server_default=func.now())

    session = relationship(Session, back_populates="captures")
    lab_results = relationship("LabJob", back_populates="sample")


class LabJob(Base):
    __tablename__ = "lab_jobs"

    id = Column(Integer, primary_key=True)
    sample_id = Column(Integer, ForeignKey("samples.id"))
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    container_id = Column(String(64), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    results = Column(JSON, nullable=True)  # YARA, MITRE, IOC results

    sample = relationship(Sample, back_populates="lab_results")
