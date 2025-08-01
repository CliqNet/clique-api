# app/models
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, validator
from prisma.enums import UserType #, AccountStatus
import re


# ===== PYDANTIC MODELS =====
class SignupRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    firstName: str
    lastName: str
    userType: UserType

    # Optional profile data
    # For creators
    bio: Optional[str] = None
    niche: Optional[list[str]] = None

    # For companies
    companyName: Optional[str] = None
    industry: Optional[str] = None
    website: Optional[str] = None
    description: Optional[str] = None

    @validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    @validator("username")
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        return v.lower()

    @validator("website")
    def validate_website(cls, v):
        if v and not re.match(r"^https?://", v):
            raise ValueError("Website must start with http:// or https://")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None  # Optional for security


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    firstName: str
    lastName: str
    userType: str
    status: str
    isVerified: bool
    avatar: Optional[str]
    phone: Optional[str] = None
    location: Optional[str] = None
    createdAt: datetime
    profile: Optional[dict] = None  # Creator/Company/Admin profile
    roles: Optional[List[dict]] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    newPassword: str

    @validator("newPassword")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v
