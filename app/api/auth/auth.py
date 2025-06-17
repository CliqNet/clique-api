# app/api/auth/auth.py
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt
import jwt
from prisma.enums import UserType, AccountStatus
from app.models.auth import SignupRequest, LoginRequest, TokenResponse, UserResponse, PasswordResetConfirm, PasswordResetRequest
from app.lib.prisma import prisma
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


# ===== UTILITY FUNCTIONS =====
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=settings.ACCESS_TOKEN_EXPIRE_HOURS)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(user_id: str) -> str:
    """Create refresh token"""
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"sub": user_id, "exp": expire, "type": "refresh"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(credentials.credentials, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = await prisma.user.find_unique(
        where={"id": user_id},
        include={
            "creator": True,
            "company": True,
            "admin": True,
            "roles": {
                "include": {
                    "role": {
                        "include": {
                            "permissions": {
                                "include": {
                                    "permission": True
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    
    if user is None:
        raise credentials_exception
    
    if user.status == AccountStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended"
        )
    
    return user

def format_user_response(user):
    """Format user response with deduplicated permissions"""
    
    user_roles = []
    
    for user_role in user.roles:
        role = user_role.role
        user_roles.append({
            "id": role.id,
            "name": role.name,
            "description": role.description
        })
    
    # Determine profile based on user type
    profile_data = None
    if user.userType == UserType.CREATOR and user.creator:
        profile_data = {
            "role": "CREATOR",
            "bio": user.creator.bio,
            "niche": user.creator.niche,
            "totalFollowers": user.creator.totalFollowers,
            "avgEngagement": user.creator.avgEngagement,
            "isVerified": user.creator.isVerified,
            "plan": user.creator.plan
        }
    elif user.userType == UserType.COMPANY and user.company:
        profile_data = {
            "role": "COMPANY",
            "companyName": user.company.companyName,
            "industry": user.company.industry,
            "website": user.company.website,
            "description": user.company.description,
            "plan": user.company.plan
        }
    elif user.userType == UserType.ADMIN and user.admin:
        profile_data = {
            "role": user.admin.role,  # This will be SUPER_ADMIN, ADMIN, or MODERATOR
        }
    
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "firstName": user.firstName,
        "lastName": user.lastName,
        "userType": user.userType,
        "status": user.status,
        "isVerified": user.isVerified,
        "avatar": user.avatar,
        "createdAt": user.createdAt.isoformat() if user.createdAt else None,
        "profile": profile_data
    }


# ===== AUTH ROUTES =====
@router.post("/signup", response_model=TokenResponse)
async def signup(request: SignupRequest):
    """User registration"""
    
    # Check if user already exists
    existing_user = await prisma.user.find_first(
        where={
            "OR": [
                {"email": request.email},
                {"username": request.username}
            ]
        }
    )
    
    if existing_user:
        if existing_user.email == request.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
    
    # Hash password
    hashed_password = hash_password(request.password)
    
    # Create user
    user = await prisma.user.create(
        data={
            "email": request.email,
            "username": request.username,
            "password": hashed_password,
            "firstName": request.firstName,
            "lastName": request.lastName,
            "userType": request.userType,
            "status": AccountStatus.PENDING_VERIFICATION,
        }
    )
    
    # Create profile based on user type
    if request.userType == UserType.CREATOR:
        await prisma.creatorprofile.create(
            data={
                "userId": user.id,
                "bio": request.bio,
                "niche": request.niche or [],
            }
        )
        
        # Assign creator role
        creator_role = await prisma.role.find_first(where={"name": "creator_basic"})
        if creator_role:
            await prisma.userrole.create(
                data={"userId": user.id, "roleId": creator_role.id}
            )
    
    elif request.userType == UserType.COMPANY:
        if not request.companyName:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Company name is required for company accounts"
            )
        
        await prisma.companyprofile.create(
            data={
                "userId": user.id,
                "companyName": request.companyName,
                "industry": request.industry or "",
                "website": request.website,
                "description": request.description,
            }
        )
        
        # Assign company role
        company_role = await prisma.role.find_first(where={"name": "company_basic"})
        if company_role:
            await prisma.userrole.create(
                data={"userId": user.id, "roleId": company_role.id}
            )
    
    # Get user with profile for response
    user_with_profile = await prisma.user.find_unique(
        where={"id": user.id},
        include={
            "creator": True,
            "company": True,
            "admin": True,
            "roles": {
                "include": {
                    "role": {
                        "include": {
                            "permissions": {
                                "include": {
                                    "permission": True
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    
    # Create tokens
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    # Store session
    await prisma.usersession.create(
        data={
            "userId": user.id,
            "token": refresh_token,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        }
    )
    
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        user=format_user_response(user_with_profile)
    )

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """User login"""
    
    # Find user with proper includes
    user = await prisma.user.find_unique(
        where={"email": request.email},
        include={
            "creator": True,
            "company": True,
            "admin": True,
            "roles": {
                "include": {
                    "role": {
                        "include": {
                            "permissions": {
                                "include": {
                                    "permission": True
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    
    if not user or not verify_password(request.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if user.status == AccountStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended"
        )
    
    if user.status == AccountStatus.DEACTIVATED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deactivated"
        )
    
    # Update last login
    await prisma.user.update(
        where={"id": user.id},
        data={"lastLoginAt": datetime.now(timezone.utc)}
    )
    
    # Create tokens
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    # Store session
    await prisma.usersession.create(
        data={
            "userId": user.id,
            "token": refresh_token,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        }
    )
    
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        user=format_user_response(user)
    )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user = Depends(get_current_user)):
    """Get current user information"""
    return format_user_response(current_user)

@router.post("/logout")
async def logout(current_user = Depends(get_current_user)):
    """User logout - invalidate all sessions"""
    await prisma.usersession.delete_many(
        where={"userId": current_user.id}
    )
    return {"message": "Successfully logged out"}

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Refresh access token"""
    try:
        payload = jwt.decode(credentials.credentials, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if user_id is None or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Check if session exists
    session = await prisma.usersession.find_first(
        where={"token": credentials.credentials, "userId": user_id}
    )
    
    if not session or session.expiresAt < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Get user
    user = await prisma.user.find_unique(
        where={"id": user_id},
        include={
            "creator": True,
            "company": True,
            "admin": True,
            "roles": {
                "include": {
                    "role": {
                        "include": {
                            "permissions": {
                                "include": {
                                    "permission": True
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    # Create new access token
    access_token = create_access_token({"sub": user.id})
    
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        user=format_user_response(user)
    )

@router.post("/password-reset")
async def request_password_reset(request: PasswordResetRequest):
    """Request password reset"""
    user = await prisma.user.find_unique(where={"email": request.email})
    
    if not user:
        # Don't reveal if email exists or not
        return {"message": "If the email exists, a reset link has been sent"}
    
    # Generate reset token
    reset_token = create_access_token(
        {"sub": user.id, "type": "reset"},
        expires_delta=timedelta(hours=1)
    )
    
    # Update user with reset token
    await prisma.user.update(
        where={"id": user.id},
        data={
            "passwordResetToken": reset_token,
            "passwordResetExpiresAt": datetime.now(timezone.utc) + timedelta(hours=1)
        }
    )
    
    # TODO: Send email with reset link
    # For now, return the token (remove this in production)
    return {
        "message": "Password reset link sent to email",
        "reset_token": reset_token  # Remove this in production
    }

@router.post("/password-reset/confirm")
async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm password reset"""
    try:
        payload = jwt.decode(request.token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if user_id is None or token_type != "reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reset token"
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )
    
    # Find user and verify token
    user = await prisma.user.find_unique(where={"id": user_id})
    
    if not user or user.passwordResetToken != request.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )
    
    if user.passwordResetExpiresAt < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token expired"
        )
    
    # Update password
    hashed_password = hash_password(request.newPassword)
    await prisma.user.update(
        where={"id": user.id},
        data={
            "password": hashed_password,
            "passwordResetToken": None,
            "passwordResetExpiresAt": None
        }
    )
    
    # Invalidate all sessions
    await prisma.usersession.delete_many(where={"userId": user.id})
    
    return {"message": "Password reset successful"}

# ===== ADMIN ROUTES =====
@router.get("/users")
async def list_users(
    current_user = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100
):
    """List users (admin only)"""
    if current_user.userType != UserType.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    users = await prisma.user.find_many(
        skip=skip,
        take=limit,
        include={
            "creator": True,
            "company": True,
            "admin": True,
        }
    )
    
    return {
        "users": [format_user_response(user) for user in users],
        "total": len(users)
    }

# @router.get("/permissions")
# async def get_user_permissions(current_user: User = Depends(get_current_user)):
#     # Return user's permissions when needed
#     permissions = get_user_permissions(current_user.id)
#     return [perm.name for perm in permissions]