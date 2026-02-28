from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.db import get_db
from app.models.session import Canary

router = APIRouter()

@router.get("/")
async def list_canaries(is_active: bool = None, limit: int = 100, db: AsyncSession = Depends(get_db)):
    query = select(Canary).order_by(Canary.created_at.desc()).limit(limit)
    if is_active is not None:
        query = query.where(Canary.is_active == is_active)
    result = await db.execute(query)
    canaries = result.scalars().all()
    return [{'id': c.id, 'name': c.name, 'canary_type': c.canary_type, 'path': c.path, 'hit_count': c.hit_count, 'is_active': c.is_active} for c in canaries]

@router.post("/")
async def create_canary(name: str, canary_type: str, path: str = None, content: str = None, db: AsyncSession = Depends(get_db)):
    canary = Canary(name=name, canary_type=canary_type, path=path, content=content, is_active=True)
    db.add(canary)
    await db.commit()
    await db.refresh(canary)
    return {'id': canary.id, 'name': canary.name, 'status': 'created'}

@router.get("/{canary_id}")
async def get_canary(canary_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Canary).where(Canary.id == canary_id))
    canary = result.scalar_one_or_none()
    if not canary:
        raise HTTPException(status_code=404, detail='Canary not found')
    return {'id': canary.id, 'name': canary.name, 'canary_type': canary.canary_type, 'path': canary.path, 'content': canary.content, 'hit_count': canary.hit_count, 'is_active': canary.is_active}

@router.delete("/{canary_id}")
async def delete_canary(canary_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Canary).where(Canary.id == canary_id))
    canary = result.scalar_one_or_none()
    if not canary:
        raise HTTPException(status_code=404, detail='Canary not found')
    await db.delete(canary)
    await db.commit()
    return {'status': 'deleted', 'id': canary_id}

@router.post("/{canary_id}/hit")
async def hit_canary(canary_id: int, session_id: str = None, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Canary).where(Canary.id == canary_id))
    canary = result.scalar_one_or_none()
    if not canary:
        raise HTTPException(status_code=404, detail='Canary not found')
    canary.hit_count += 1
    await db.commit()
    return {'status': 'hit', 'canary_id': canary_id, 'hit_count': canary.hit_count}
