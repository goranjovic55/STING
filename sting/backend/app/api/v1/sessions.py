from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.db import get_db
from app.models.session import Session as DBSession, SessionWrite, Event, Sample, SessionState
from app.verdict.engine import VerdictEngine
import uuid

router = APIRouter()
verdict_engine = VerdictEngine()

@router.get("/")
async def list_sessions(limit: int = 50, offset: int = 0, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBSession).order_by(DBSession.created_at.desc()).limit(limit).offset(offset))
    sessions = result.scalars().all()
    return [{'id': s.id, 'ip_address': s.ip_address, 'port': s.port, 'protocol': s.protocol, 'score': s.score, 'state': s.state.value if s.state else 'hostile', 'created_at': s.created_at.isoformat() if s.created_at else None} for s in sessions]

@router.get("/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBSession).where(DBSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail='Session not found')
    events_result = await db.execute(select(Event).where(Event.session_id == session_id).order_by(Event.created_at.desc()))
    events = events_result.scalars().all()
    return {'id': session.id, 'ip_address': session.ip_address, 'port': session.port, 'protocol': session.protocol, 'score': session.score, 'state': session.state.value if session.state else 'hostile', 'events': [{'id': e.id, 'event_type': e.event_type, 'payload': e.payload, 'score_delta': e.score_delta, 'created_at': e.created_at.isoformat() if e.created_at else None} for e in events]}

@router.post("/")
async def create_session(ip_address: str, port: int, protocol: str, db: AsyncSession = Depends(get_db)):
    session_id = str(uuid.uuid4())
    session = DBSession(id=session_id, ip_address=ip_address, port=port, protocol=protocol, score=100, state=SessionState.HOSTILE)
    db.add(session)
    await db.commit()
    return {'id': session_id, 'status': 'created'}

@router.post("/{session_id}/nuke")
async def nuke_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBSession).where(DBSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail='Session not found')
    await db.delete(session)
    await db.commit()
    return {'status': 'nuked', 'session_id': session_id}

@router.post("/{session_id}/commit")
async def commit_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBSession).where(DBSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail='Session not found')
    session.state = SessionState.NUKE_COMMITTED
    await db.commit()
    return {'status': 'committed', 'session_id': session_id}

@router.post("/{session_id}/lab")
async def lab_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBSession).where(DBSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail='Session not found')
    session.state = SessionState.LAB_TRANSFERRED
    await db.commit()
    return {'status': 'lab_transfer', 'session_id': session_id}

@router.get("/{session_id}/verdict")
async def get_verdict(session_id: str):
    verdict = verdict_engine.get_verdict(session_id)
    return {'session_id': verdict.session_id, 'score': verdict.score, 'state': verdict.state}
