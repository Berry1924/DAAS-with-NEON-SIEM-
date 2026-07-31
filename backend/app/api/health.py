from fastapi import APIRouter
from backend.app.core.config import settings

router = APIRouter()

@router.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "app": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }
