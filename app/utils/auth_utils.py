# app/api/auth/auth_utils.py
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt
import jwt
from prisma.enums import UserType, AccountStatus
from app.lib.prisma import prisma
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


# ===== UTILITY FUNCTIONS =====
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            hours=settings.ACCESS_TOKEN_EXPIRE_HOURS
        )

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(user_id: str) -> str:
    """Create refresh token"""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    to_encode = {"sub": user_id, "exp": expire, "type": "refresh"}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
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
                        "include": {"permissions": {"include": {"permission": True}}}
                    }
                }
            },
        },
    )

    if user is None:
        raise credentials_exception

    if user.status == AccountStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account suspended"
        )

    return user


def format_user_response(user):
    """Format user response with deduplicated permissions"""

    user_roles = []

    for user_role in user.roles:
        role = user_role.role
        user_roles.append(
            {"id": role.id, "name": role.name, "description": role.description}
        )

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
            "plan": user.creator.plan,
        }
    elif user.userType == UserType.COMPANY and user.company:
        profile_data = {
            "role": "COMPANY",
            "companyName": user.company.companyName,
            "industry": user.company.industry,
            "website": user.company.website,
            "description": user.company.description,
            "plan": user.company.plan,
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
        "profile": profile_data,
    }
