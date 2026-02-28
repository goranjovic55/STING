from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.db import get_db
from app.models.session import LabJob, Sample
from datetime import datetime

router = APIRouter()

@router.get("/")
async def list_lab_jobs(status: str = None, limit: int = 50, db: AsyncSession = Depends(get_db)):
    query = select(LabJob).order_by(LabJob.started_at.desc()).limit(limit)
    if status:
        query = query.where(LabJob.status == status)
    result = await db.execute(query)
    jobs = result.scalars().all()
    return [{'id': j.id, 'sample_id': j.sample_id, 'status': j.status, 'container_id': j.container_id, 'started_at': j.started_at.isoformat() if j.started_at else None, 'completed_at': j.completed_at.isoformat() if j.completed_at else None} for j in jobs]

@router.post("/")
async def create_lab_job(sample_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Sample).where(Sample.id == sample_id))
    sample = result.scalar_one_or_none()
    if not sample:
        raise HTTPException(status_code=404, detail='Sample not found')
    job = LabJob(sample_id=sample_id, status='pending')
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return {'id': job.id, 'sample_id': sample_id, 'status': 'pending'}

@router.get("/{job_id}")
async def get_lab_job(job_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LabJob).where(LabJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail='Lab job not found')
    return {'id': job.id, 'sample_id': job.sample_id, 'status': job.status, 'container_id': job.container_id, 'started_at': job.started_at.isoformat() if job.started_at else None, 'completed_at': job.completed_at.isoformat() if job.completed_at else None, 'results': job.results}

@router.post("/{job_id}/start")
async def start_lab_job(job_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LabJob).where(LabJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail='Lab job not found')
    job.status = 'running'
    job.container_id = f'sting-lab-{job_id}'
    job.started_at = datetime.utcnow()
    await db.commit()
    return {'id': job.id, 'status': 'running', 'container_id': job.container_id}
