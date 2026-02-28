# STING 2.0 - Events API
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.core.db import get_db
from app.models.session import Event
from app.main import manager

router = APIRouter()


class EventCreate(BaseModel):
    session_id: str
    event_type: str
    payload: Optional[dict] = None
    score_delta: int = 0


class EventResponse(BaseModel):
    id: int
    session_id: str
    event_type: str
    payload: Optional[dict]
    score_delta: int
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=List[EventResponse])
async def list_events(
    session_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    query = select(Event).order_by(Event.created_at.desc()).limit(limit)
    if session_id:
        query = query.where(Event.session_id == session_id)
    if event_type:
        query = query.where(Event.event_type == event_type)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(event_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("/", response_model=EventResponse)
async def create_event(event: EventCreate, db: AsyncSession = Depends(get_db)):
    # Create DB record
    db_event = Event(
        session_id=event.session_id,
        event_type=event.event_type,
        payload=event.payload,
        score_delta=event.score_delta
    )
    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)

    # Broadcast via WebSocket
    await manager.broadcast(
        "events",
        {
            "type": "event",
            "session_id": event.session_id,
            "event_type": event.event_type,
            "payload": event.payload,
            "score_delta": event.score_delta,
            "timestamp": db_event.created_at.isoformat()
        }
    )

    return db_event


@router.get("/session/{session_id}", response_model=List[EventResponse])
async def get_session_events(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Event).where(Event.session_id == session_id).order_by(Event.created_at.desc())
    )
    return result.scalars().all()
