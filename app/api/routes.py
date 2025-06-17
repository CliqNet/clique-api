# app/api/routes.py
from fastapi import APIRouter
from app.core.config import settings
from app.api.auth.auth import router as auth_router
from app.api.users.users import router as users_router

router = APIRouter()

router.include_router(auth_router)
router.include_router(users_router)

@router.get("/")
def read_root():
    return {
        "message": f"Welcome to {settings.APP_NAME}!",
        "env": settings.APP_ENV,
        "debug": settings.DEBUG
    }

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "env": settings.APP_ENV
    }