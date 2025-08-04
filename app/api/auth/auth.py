# app/api/auth/auth.py
from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from ...utils.auth_utils import get_current_user
from app.models.auth import (
    SignupRequest,
    LoginRequest,
    TokenResponse,
    UserResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
)

from ...services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


# ===== AUTH ROUTES =====
@router.post("/signup", response_model=TokenResponse)
async def signup(request: SignupRequest):
    """User registration"""
    return await auth_service.signup_user(request)


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """User login"""
    return await auth_service.login_user(request)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user=Depends(get_current_user)):
    """Get current user information with full profile data"""
    return await auth_service.get_current_user_info(current_user)

@router.post("/logout")
async def logout(request: Request, current_user=Depends(get_current_user)):
    """User logout - invalidate all sessions"""
    return await auth_service.login_user(request, current_user)



@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Refresh access token"""
    return await auth_service.refresh_token(credentials)



@router.post("/password-reset")
async def request_password_reset(request: PasswordResetRequest):
    """Request password reset"""
    return await auth_service.request_password_reset(request)


@router.post("/password-reset/confirm")
async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm password reset"""
    return await auth_service.confirm_password_reset(request)
