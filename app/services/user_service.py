# app/services/user_service.py
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from prisma.enums import UserType, AccountStatus, AdminRole, PlanType

from app.lib.prisma import prisma
from app.core.config import settings
from app.utils.auth_utils import hash_password
from app.models.user import (
    CreateUserRequest,
    UpdateUserRequest,
    UserListResponse,
    Pagination,
    ChangePasswordRequest,
    ResetPasswordRequest,
    AssignRoleRequest,
    UserStatusUpdate,
    UserActiveUpdate,
)
from app.utils.user_utils import (
    format_user_response,
    fetch_users_by_type,
)


class UserService:
    """Service class containing all user-related business logic"""

    @staticmethod
    async def get_users_by_type(user_type: UserType, page: int, limit: int) -> UserListResponse:
        """Get users filtered by type with pagination"""
        try:
            return await fetch_users_by_type(user_type, page, limit)
        except Exception as e:
            print(f"Error in get_users_by_type: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error retrieving users"
            )

    @staticmethod
    async def get_all_users(
        page: int,
        limit: int,
        include_profiles: bool = True,
        include_roles: bool = False
    ) -> UserListResponse:
        """Get all users with pagination and optional includes"""
        skip = (page - 1) * limit

        users = await prisma.user.find_many(
            include={
                "creator": include_profiles,
                "company": include_profiles,
                "admin": include_profiles,
                "roles": {"include": {"role": True}} if include_roles else False,
            },
            skip=skip,
            take=limit,
            order={"createdAt": "desc"},
        )

        total = await prisma.user.count()

        return UserListResponse(
            users=[
                format_user_response(user, include_profiles, include_roles) 
                for user in users
            ],
            pagination=Pagination(
                total=total, 
                page=page, 
                limit=limit, 
                totalPages=(total + limit - 1) // limit
            ),
        )

    @staticmethod
    async def get_user_by_id(
        user_id: str,
        include_profiles: bool = True,
        include_roles: bool = False
    ):
        """Get a specific user by ID"""
        include_clause = {}
        if include_profiles:
            include_clause.update({"creator": True, "company": True, "admin": True})

        if include_roles:
            include_clause["roles"] = {"include": {"role": True}}

        user = await prisma.user.find_unique(
            where={"id": user_id}, 
            include=include_clause
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        return format_user_response(user, include_profiles, include_roles)

    @staticmethod
    async def get_user_by_username(username: str, include_profiles: bool = True):
        """Get user by username"""
        user = await prisma.user.find_unique(
            where={"username": username},
            include={
                "creator": include_profiles,
                "company": include_profiles,
                "admin": include_profiles,
            },
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        return format_user_response(user, include_profiles)

    @staticmethod
    async def create_user(user_data: CreateUserRequest):
        """Create a new user with appropriate profile"""
        # Check if user already exists
        existing_user = await prisma.user.find_first(
            where={"OR": [{"email": user_data.email}, {"username": user_data.username}]}
        )

        if existing_user:
            if existing_user.email == user_data.email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered",
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, 
                    detail="Username already taken"
                )

        # Hash password
        hashed_password = hash_password(user_data.password)

        # Create user
        user = await prisma.user.create(
            data={
                "email": user_data.email,
                "username": user_data.username,
                "password": hashed_password,
                "firstName": user_data.firstName,
                "lastName": user_data.lastName,
                "userType": user_data.userType,
                "status": user_data.status or AccountStatus.ACTIVE,
                "isVerified": user_data.isVerified or False,
            }
        )

        # Create profile based on user type
        await UserService._create_user_profile(user.id, user_data)

        # Get user with profile for response
        user_with_profile = await prisma.user.find_unique(
            where={"id": user.id}, 
            include={"creator": True, "company": True, "admin": True}
        )

        return format_user_response(user_with_profile)

    @staticmethod
    async def _create_user_profile(user_id: str, user_data: CreateUserRequest):
        """Helper method to create user profile based on type"""
        if user_data.userType == UserType.CREATOR:
            await prisma.creatorprofile.create(
                data={
                    "userId": user_id,
                    "bio": user_data.bio or "",
                    "niche": user_data.niche or [],
                    "plan": user_data.plan or PlanType.FREE,
                }
            )
        elif user_data.userType == UserType.COMPANY:
            if not user_data.companyName:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Company name is required for company accounts",
                )

            await prisma.companyprofile.create(
                data={
                    "userId": user_id,
                    "companyName": user_data.companyName,
                    "industry": user_data.industry or "",
                    "website": user_data.website,
                    "description": user_data.description or "",
                    "plan": user_data.plan or PlanType.FREE,
                }
            )
        elif user_data.userType == UserType.ADMIN:
            await prisma.adminprofile.create(
                data={
                    "userId": user_id, 
                    "role": user_data.adminRole or AdminRole.MODERATOR
                }
            )

    @staticmethod
    async def update_user(user_id: str, user_data: UpdateUserRequest):
        """Update user information and profile"""
        existing_user = await prisma.user.find_unique(where={"id": user_id})
        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        # Check for email/username conflicts
        await UserService._check_user_conflicts(user_id, user_data)

        # Prepare update data for user fields
        update_data = UserService._prepare_user_update_data(user_data)

        # Update user
        await prisma.user.update(
            where={"id": user_id},
            data=update_data,
        )

        # Update profile data if provided
        if user_data.profileData:
            await UserService._update_user_profile(user_id, existing_user.userType, user_data.profileData)

        # Get updated user with profile
        final_user = await prisma.user.find_unique(
            where={"id": user_id}, 
            include={"creator": True, "company": True, "admin": True}
        )

        return format_user_response(final_user)

    @staticmethod
    async def _check_user_conflicts(user_id: str, user_data: UpdateUserRequest):
        """Check for email/username conflicts during update"""
        if user_data.email or user_data.username:
            conflicts = []
            if user_data.email:
                conflicts.append({"email": user_data.email})
            if user_data.username:
                conflicts.append({"username": user_data.username})

            conflicting_user = await prisma.user.find_first(
                where={"AND": [{"id": {"not": user_id}}, {"OR": conflicts}]}
            )
            
            if conflicting_user:
                if conflicting_user.email == user_data.email:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already in use",
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Username already taken",
                    )

    @staticmethod
    def _prepare_user_update_data(user_data: UpdateUserRequest) -> Dict[str, Any]:
        """Prepare update data for user fields"""
        update_data = {}
        for field in [
            "email", "username", "firstName", "lastName", 
            "status", "isVerified", "phone", "location"
        ]:
            value = getattr(user_data, field, None)
            if value is not None:
                update_data[field] = value

        # Handle password update if provided
        if hasattr(user_data, "password") and user_data.password:
            update_data["password"] = hash_password(user_data.password)

        return update_data

    @staticmethod
    async def _update_user_profile(user_id: str, user_type: UserType, profile_data):
        """Update user profile based on user type"""
        profile_update = {}

        if user_type == UserType.CREATOR:
            for field in ["bio", "niche", "plan"]:
                if hasattr(profile_data, field) and getattr(profile_data, field) is not None:
                    profile_update[field] = getattr(profile_data, field)

            if profile_update:
                await prisma.creatorprofile.update(
                    where={"userId": user_id}, 
                    data=profile_update
                )

        elif user_type == UserType.COMPANY:
            for field in ["companyName", "industry", "website", "description", "plan"]:
                if hasattr(profile_data, field) and getattr(profile_data, field) is not None:
                    profile_update[field] = getattr(profile_data, field)

            if profile_update:
                await prisma.companyprofile.update(
                    where={"userId": user_id}, 
                    data=profile_update
                )

        # Add admin profile update logic if needed

    @staticmethod
    async def delete_user(user_id: str, hard_delete: bool = False):
        """Delete user (soft or hard delete)"""
        user = await prisma.user.find_unique(where={"id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        if hard_delete:
            # Hard delete - remove user and all related data
            await prisma.user.delete(where={"id": user_id})
        else:
            # Soft delete - deactivate account
            await prisma.user.update(
                where={"id": user_id},
                data={"status": AccountStatus.DEACTIVATED, "isActive": False},
            )

        return {"message": "User deleted successfully"}

    @staticmethod
    async def update_user_status(user_id: str, status_data: UserStatusUpdate):
        """Update user status"""
        user = await prisma.user.update(
            where={"id": user_id},
            data={"status": status_data.status},
            include={"creator": True, "company": True, "admin": True},
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        return format_user_response(user)

    @staticmethod
    async def toggle_user_active(user_id: str, active_data: UserActiveUpdate):
        """Activate/Deactivate user"""
        user = await prisma.user.update(
            where={"id": user_id},
            data={"isActive": active_data.isActive},
            include={"creator": True, "company": True, "admin": True},
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        return format_user_response(user)

    @staticmethod
    async def verify_user(user_id: str):
        """Verify user email"""
        user = await prisma.user.update(
            where={"id": user_id},
            data={"isVerified": True, "status": AccountStatus.ACTIVE},
            include={"creator": True, "company": True, "admin": True},
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        return format_user_response(user)

    @staticmethod
    async def change_user_password(user_id: str, password_data: ChangePasswordRequest):
        """Change user password (admin function)"""
        user = await prisma.user.find_unique(where={"id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        # Hash new password
        hashed_password = hash_password(password_data.newPassword)

        # Update password
        await prisma.user.update(
            where={"id": user_id}, 
            data={"password": hashed_password}
        )

        # Invalidate all user sessions
        await prisma.usersession.delete_many(where={"userId": user_id})

        return {"message": "Password changed successfully"}

    @staticmethod
    async def reset_password(reset_data: ResetPasswordRequest):
        """Reset password with token (public endpoint)"""
        try:
            import jwt

            payload = jwt.decode(
                reset_data.token, 
                settings.SECRET_KEY, 
                algorithms=[settings.ALGORITHM]
            )
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

        if not user or user.passwordResetToken != reset_data.token:
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
        hashed_password = hash_password(reset_data.newPassword)
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

    @staticmethod
    async def assign_role(user_id: str, role_data: AssignRoleRequest):
        """Assign role to user"""
        # Check if user exists
        user = await prisma.user.find_unique(where={"id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )

        # Check if role exists
        role = await prisma.role.find_unique(where={"id": role_data.roleId})
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Role not found"
            )

        # Check if user already has this role
        existing_role = await prisma.userrole.find_first(
            where={"userId": user_id, "roleId": role_data.roleId}
        )

        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="User already has this role"
            )

        # Assign role
        await prisma.userrole.create(
            data={"userId": user_id, "roleId": role_data.roleId}
        )

        # Return updated user
        updated_user = await prisma.user.find_unique(
            where={"id": user_id},
            include={
                "creator": True,
                "company": True,
                "admin": True,
                "roles": {"include": {"role": True}},
            },
        )

        return format_user_response(updated_user, include_roles=True)

    @staticmethod
    async def remove_role(user_id: str, role_id: str):
        """Remove role from user"""
        # Check if assignment exists
        user_role = await prisma.userrole.find_first(
            where={"userId": user_id, "roleId": role_id}
        )

        if not user_role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Role assignment not found"
            )

        # Remove role
        await prisma.userrole.delete(where={"id": user_role.id})

        # Return updated user
        updated_user = await prisma.user.find_unique(
            where={"id": user_id},
            include={
                "creator": True,
                "company": True,
                "admin": True,
                "roles": {"include": {"role": True}},
            },
        )

        return format_user_response(updated_user, include_roles=True)