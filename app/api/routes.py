from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()

@router.get("/")
def read_root():
    return {
        "message": f"Welcome to {settings.APP_NAME}!",
        "env": settings.APP_ENV,
        "debug": settings.DEBUG
    }