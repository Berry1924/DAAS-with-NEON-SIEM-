from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.app.core.config import settings
from backend.app.db.session import get_db

router = APIRouter()

@router.get("/health", tags=["Health"])
async def health_check(db: Session = Depends(get_db)):
    """Health check with database connectivity probe."""
    db_status = "connected"
    http_status = 200
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"
        http_status = 503

    return JSONResponse(
        status_code=http_status,
        content={
            "status": "ok" if http_status == 200 else "degraded",
            "app": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "database": db_status,
        }
    )
