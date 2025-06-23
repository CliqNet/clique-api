# app/api/routes.py
from fastapi import APIRouter
from app.core.config import settings
from app.api.auth.auth import router as auth_router
from app.api.users.users import router as users_router
from app.api.socials.social_auth_routes import router as socials_router
from app.api.websocket.websocket_routes import router as ws_router
from app.background_tasks.background_tasks import task_manager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


router = APIRouter()

router.include_router(auth_router)
router.include_router(users_router)
router.include_router(socials_router)
router.include_router(ws_router)


@router.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting Social Auth API...")
    await task_manager.start()

@router.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Social Auth API...")
    await task_manager.stop()

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