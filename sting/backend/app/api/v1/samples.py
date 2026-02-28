from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.db import get_db
from app.models.session import Sample
import hashlib, os

router = APIRouter()

@router.get("/")
async def list_samples(limit: int = 50, offset: int = 0, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Sample).order_by(Sample.captured_at.desc()).limit(limit).offset(offset))
    samples = result.scalars().all()
    return [{'id': s.id, 'sha256': s.sha256, 'filename': s.filename, 'file_size': s.file_size, 'file_type': s.file_type, 'source_ip': s.source_ip, 'session_id': s.session_id, 'captured_at': s.captured_at.isoformat() if s.captured_at else None} for s in samples]

@router.post("/")
async def upload_sample(file: UploadFile = File(...), session_id: str = None, source_ip: str = None, db: AsyncSession = Depends(get_db)):
    content = await file.read()
    sha256_hash = hashlib.sha256(content).hexdigest()
    sample = Sample(sha256=sha256_hash, filename=file.filename, file_size=len(content), session_id=session_id, source_ip=source_ip)
    db.add(sample)
    await db.commit()
    await db.refresh(sample)
    os.makedirs('/var/lib/sting/samples', exist_ok=True)
    with open(f'/var/lib/sting/samples/{sha256_hash}', 'wb') as f:
        f.write(content)
    return {'id': sample.id, 'sha256': sha256_hash, 'filename': file.filename, 'status': 'uploaded'}

@router.get("/{sample_id}")
async def get_sample(sample_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Sample).where(Sample.id == sample_id))
    sample = result.scalar_one_or_none()
    if not sample:
        raise HTTPException(status_code=404, detail='Sample not found')
    return {'id': sample.id, 'sha256': sample.sha256, 'filename': sample.filename, 'file_size': sample.file_size, 'file_type': sample.file_type, 'source_ip': sample.source_ip}
