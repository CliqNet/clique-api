from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer
import jwt
from ..utils.auth_utils import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    get_current_user,
    format_user_response,
)
from prisma.enums import UserType, AccountStatus
from app.models.auth import (
    SignupRequest,
    LoginRequest,
    TokenResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
)
from app.lib.prisma import prisma
from app.core.config import settings
import bcrypt

security = HTTPBearer()

async def login_user(request: LoginRequest):
    """User login"""

    # Find user with minimal data for authentication
    user = await prisma.user.find_unique(where={"email": request.email})

    if not user or not verify_password(request.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )

    if user.status == AccountStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account suspended"
        )

    if user.status == AccountStatus.DEACTIVATED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated"
        )

    # Update last login
    await prisma.user.update(
        where={"id": user.id}, data={"lastLoginAt": datetime.now(timezone.utc)}
    )

    # Create tokens
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)

    # Store session
    await prisma.usersession.create(
        data={
            "userId": user.id,
            "token": refresh_token,
            "expiresAt": datetime.now(timezone.utc)
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        }
    )

    # Fetch full user profile (same as `/me`)
    full_user = await prisma.user.find_unique(
        where={"id": user.id},
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

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        refresh_token=refresh_token,
        user=format_user_response(full_user)
    )

async def signup_user(request: SignupRequest):
     # Check if user already exists
    existing_user = await prisma.user.find_first(
        where={"OR": [{"email": request.email}, {"username": request.username}]}
    )

    if existing_user:
        if existing_user.email == request.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken"
            )

    hashed_password = bcrypt.hashpw(
        request.password.encode("utf-8"),
        bcrypt.gensalt(rounds=12),  # Higher cost for production
    ).decode("utf-8")

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
            "emailVerificationToken": create_access_token(
                {"sub": request.email, "type": "email_verification"},
                expires_delta=timedelta(hours=24),
            ),
        }
    )

    # Create profile based on user type
    if request.userType == UserType.CREATOR:
        await prisma.creatorprofile.create(
            data={
                "userId": user.id,
                "bio": request.bio or "",
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
                detail="Company name is required for company accounts",
            )

        await prisma.companyprofile.create(
            data={
                "userId": user.id,
                "companyName": request.companyName,
                "industry": request.industry or "",
                "website": request.website or "",
                "description": request.description or "",
            }
        )

        # Assign company role
        company_role = await prisma.role.find_first(where={"name": "company_basic"})
        if company_role:
            await prisma.userrole.create(
                data={"userId": user.id, "roleId": company_role.id}
            )

    # Create tokens
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)


    # Get user with profile for response
    full_user = await prisma.user.find_unique(
        where={"id": user.id},
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


    # Store session
    await prisma.usersession.create(
        data={
            "userId": user.id,
            "token": refresh_token,
            "expiresAt": datetime.now(timezone.utc)
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        }
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        refresh_token=refresh_token,
        user=format_user_response(full_user)

    )

async def get_current_user_info(current_user=Depends(get_current_user)):
    """Get current user information with full profile data"""

    # Fetch complete user data with all necessary includes
    user = await prisma.user.find_unique(
        where={"id": current_user.id},
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

    return format_user_response(user)

async def logout_user(request: Request, current_user=Depends(get_current_user)):
    """User logout - invalidate all sessions"""

    # Get token from request
    authorization = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]

        # Decode to get JTI (JWT ID) and expiration
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            jti = payload.get("jti")  # You need to add JTI to your token creation
            exp = payload.get("exp")

            # Add to blacklist
            await prisma.tokenblacklist.create(
                data={
                    "tokenJti": jti,
                    "expiresAt": datetime.fromtimestamp(exp, timezone.utc),
                }
            )
        except jwt.InvalidTokenError:
            pass

    await prisma.usersession.delete_many(where={"userId": current_user.id})
    return {"message": "Successfully logged out"}

async def refresh_token(credentials):
    """Refresh access token"""
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")

        if user_id is None or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    # Check if session exists
    session = await prisma.usersession.find_first(
        where={"token": credentials.credentials, "userId": user_id}
    )

    if not session or session.expiresAt < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
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
                        "include": {"permissions": {"include": {"permission": True}}}
                    }
                }
            },
        },
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )

    # Create new access token
    access_token = create_access_token({"sub": user.id})

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        user=format_user_response(user),
    )

async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm password reset"""
    try:
        payload = jwt.decode(
            request.token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")

        if user_id is None or token_type != "reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token"
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token"
        )

    # Find user and verify token
    user = await prisma.user.find_unique(where={"id": user_id})

    if not user or user.passwordResetToken != request.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token"
        )

    if user.passwordResetExpiresAt < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Reset token expired"
        )

    # Update password
    hashed_password = hash_password(request.newPassword)
    await prisma.user.update(
        where={"id": user.id},
        data={
            "password": hashed_password,
            "passwordResetToken": None,
            "passwordResetExpiresAt": None,
        },
    )

    # Invalidate all sessions
    await prisma.usersession.delete_many(where={"userId": user.id})

    return {"message": "Password reset successful"}

async def request_password_reset(request: PasswordResetRequest):
    """Request password reset"""
    user = await prisma.user.find_unique(where={"email": request.email})

    if not user:
        # Don't reveal if email exists or not
        return {"message": "If the email exists, a reset link has been sent"}

    # Generate reset token
    reset_token = create_access_token(
        {"sub": user.id, "type": "reset"}, expires_delta=timedelta(hours=1)
    )

    # Update user with reset token
    await prisma.user.update(
        where={"id": user.id},
        data={
            "passwordResetToken": reset_token,
            "passwordResetExpiresAt": datetime.now(timezone.utc) + timedelta(hours=1),
        },
    )

    # TODO: Send email with reset link
    # For now, return the token (remove this in production)
    return {
        "message": "Password reset link sent to email",
        "reset_token": reset_token,  # Remove this in production
    }

