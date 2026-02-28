from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.db import get_db
from app.models.session import Session as DBSession, Event, SessionWrite, Sample, LabJob, Canary

router = APIRouter()

@router.get("/sessions/{session_id}")
async def export_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBSession).where(DBSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail='Session not found')
    events_result = await db.execute(select(Event).where(Event.session_id == session_id).order_by(Event.created_at))
    events = events_result.scalars().all()
    writes_result = await db.execute(select(SessionWrite).where(SessionWrite.session_id == session_id))
    writes = writes_result.scalars().all()
    samples_result = await db.execute(select(Sample).where(Sample.session_id == session_id))
    samples = samples_result.scalars().all()
    return {
        'session': {'id': session.id, 'ip_address': session.ip_address, 'port': session.port, 'protocol': session.protocol, 'score': session.score, 'state': session.state.value if session.state else 'hostile', 'created_at': session.created_at.isoformat() if session.created_at else None},
        'events': [{'id': e.id, 'event_type': e.event_type, 'payload': e.payload, 'score_delta': e.score_delta} for e in events],
        'writes': [{'id': w.id, 'path': w.path, 'write_type': w.write_type} for w in writes],
        'samples': [{'id': s.id, 'sha256': s.sha256, 'filename': s.filename} for s in samples],
    }

@router.get("/canaries")
async def export_canaries(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Canary))
    canaries = result.scalars().all()
    return {'canaries': [{'id': c.id, 'name': c.name, 'canary_type': c.canary_type, 'path': c.path, 'hit_count': c.hit_count, 'is_active': c.is_active} for c in canaries]}
