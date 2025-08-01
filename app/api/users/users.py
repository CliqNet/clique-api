# app/api/users/user.py
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer
from prisma.enums import UserType, AccountStatus, AdminRole, PlanType
from app.models.user import (
    User,
    UserWithProfilesResponse,
    CreateUserRequest,
    UpdateUserRequest,
    UserListResponse,
    Pagination,
    ChangePasswordRequest,
    ResetPasswordRequest,
    AssignRoleRequest,
    BulkUpdateRequest,
    BulkDeleteRequest,
    BulkOperationResponse,
    UserStatusUpdate,
    UserActiveUpdate,
)
from app.lib.prisma import prisma
from app.core.config import settings
from app.api.auth.auth import get_current_user, hash_password
from .user_utils import (
    format_user_response,
    check_admin_permission,
    fetch_users_by_type,
)

router = APIRouter(prefix="/users", tags=["User Management"])
security = HTTPBearer()

# ===== USER TYPE SPECIFIC ENDPOINTS =====


@router.get("/creators", response_model=UserListResponse)
async def get_creators(
    # current_user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """Get list of all creator users"""
    # check_admin_permission(current_user, AdminRole.ADMIN)
    # return await fetch_users_by_type(UserType.CREATOR, page, limit)

    try:
        return await fetch_users_by_type(UserType.CREATOR, page, limit)
    except Exception as e:
        print(f"Error in get_creators: {e}")
        raise


@router.get("/companies", response_model=UserListResponse)
async def get_companies(
    # current_user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """Get list of all company users"""
    # check_admin_permission(current_user, AdminRole.ADMIN)
    return await fetch_users_by_type(UserType.COMPANY, page, limit)


@router.get("/admins", response_model=UserListResponse)
async def get_admins(
    # current_user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """Get list of all admin users"""
    # check_admin_permission(current_user, AdminRole.SUPER_ADMIN)
    return await fetch_users_by_type(UserType.ADMIN, page, limit)


# ===== USER MANAGEMENT ROUTES =====


@router.get("", response_model=UserListResponse)
async def get_users(
    # current_user = Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    includeProfiles: bool = Query(True),
    includeRoles: bool = Query(False),
):
    """Alternative approach with simpler includes"""
    skip = (page - 1) * limit

    # check_admin_permission(current_user)

    # Simple approach - include everything
    users = await prisma.user.find_many(
        include={
            "creator": True,
            "company": True,
            "admin": True,
            "roles": {"include": {"role": True}} if includeRoles else False,
        },
        skip=skip,
        take=limit,
        order={"createdAt": "desc"},
    )

    total = await prisma.user.count()

    return UserListResponse(
        users=[
            format_user_response(user, includeProfiles, includeRoles) for user in users
        ],
        pagination=Pagination(
            total=total, page=page, limit=limit, totalPages=(total + limit - 1)
        ),
    )


@router.get("/{user_id}", response_model=User)
async def get_user(
    user_id: str,
    # current_user = Depends(get_current_user),
    includeProfiles: bool = Query(True),
    includeRoles: bool = Query(False),
):
    """Get a specific user by ID"""
    # Users can view their own profile, admins can view any profile
    # if current_user.id != user_id:
    #     check_admin_permission(current_user)

    include_clause = {}
    if includeProfiles:
        include_clause.update({"creator": True, "company": True, "admin": True})

    if includeRoles:
        include_clause["roles"] = {"include": {"role": True}}

    user = await prisma.user.find_unique(where={"id": user_id}, include=include_clause)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return format_user_response(user, includeProfiles, includeRoles)


@router.get("/username/{username}", response_model=UserWithProfilesResponse)
async def get_user_by_username(
    username: str,
    current_user=Depends(get_current_user),
    includeProfiles: bool = Query(True),
):
    """Get user by username"""
    user = await prisma.user.find_unique(
        where={"username": username},
        include={
            "creator": includeProfiles,
            "company": includeProfiles,
            "admin": includeProfiles,
        },
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Users can view their own profile, admins can view any profile
    if current_user.id != user.id:
        check_admin_permission(current_user)

    return format_user_response(user, includeProfiles)


@router.post("", response_model=UserWithProfilesResponse)
async def create_user(
    user_data: CreateUserRequest, current_user=Depends(get_current_user)
):
    """Create a new user (admin only)"""
    check_admin_permission(current_user, AdminRole.ADMIN)

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
                status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken"
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
    if user_data.userType == UserType.CREATOR:
        await prisma.creatorprofile.create(
            data={
                "userId": user.id,
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
                "userId": user.id,
                "companyName": user_data.companyName,
                "industry": user_data.industry or "",
                "website": user_data.website,
                "description": user_data.description or "",
                "plan": user_data.plan or PlanType.FREE,
            }
        )
    elif user_data.userType == UserType.ADMIN:
        await prisma.adminprofile.create(
            data={"userId": user.id, "role": user_data.adminRole or AdminRole.MODERATOR}
        )

    # Get user with profile for response
    user_with_profile = await prisma.user.find_unique(
        where={"id": user.id}, include={"creator": True, "company": True, "admin": True}
    )

    return format_user_response(user_with_profile)


# @router.put("/{user_id}", response_model=UserWithProfilesResponse)
# async def update_user(
#     user_id: str,
#     user_data: UpdateUserRequest,
#     current_user = Depends(get_current_user)
# ):
#     """Update user (full update)"""
#     # Users can update their own profile, admins can update any profile
#     if current_user.id != user_id:
#         check_admin_permission(current_user)

#     # Check if user exists
#     existing_user = await prisma.user.find_unique(where={"id": user_id})
#     if not existing_user:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="User not found"
#         )

#     # Check for email/username conflicts (excluding current user)
#     if user_data.email or user_data.username:
#         conflicts = []
#         if user_data.email:
#             conflicts.append({"email": user_data.email})
#         if user_data.username:
#             conflicts.append({"username": user_data.username})

#         conflicting_user = await prisma.user.find_first(
#             where={
#                 "AND": [
#                     {"id": {"not": user_id}},
#                     {"OR": conflicts}
#                 ]
#             }
#         )

#         if conflicting_user:
#             if conflicting_user.email == user_data.email:
#                 raise HTTPException(
#                     status_code=status.HTTP_400_BAD_REQUEST,
#                     detail="Email already in use"
#                 )
#             else:
#                 raise HTTPException(
#                     status_code=status.HTTP_400_BAD_REQUEST,
#                     detail="Username already taken"
#                 )

#     # Prepare update data
#     update_data = {}
#     for field in ["email", "username", "firstName", "lastName", "status", "isVerified"]:
#         value = getattr(user_data, field, None)
#         if value is not None:
#             update_data[field] = value

#     # Handle password update
#     if user_data.password:
#         update_data["password"] = hash_password(user_data.password)

#     # Update user
#     updated_user = await prisma.user.update(
#         where={"id": user_id},
#         data=update_data,
#         include={
#             "creator": True,
#             "company": True,
#             "admin": True
#         }
#     )

#     # Update profile if provided
#     if existing_user.userType == UserType.CREATOR and any([
#         user_data.bio is not None,
#         user_data.niche is not None,
#         user_data.plan is not None
#     ]):
#         profile_update = {}
#         if user_data.bio is not None:
#             profile_update["bio"] = user_data.bio
#         if user_data.niche is not None:
#             profile_update["niche"] = user_data.niche
#         if user_data.plan is not None:
#             profile_update["plan"] = user_data.plan

#         await prisma.creatorprofile.update(
#             where={"userId": user_id},
#             data=profile_update
#         )

#     elif existing_user.userType == UserType.COMPANY and any([
#         user_data.companyName is not None,
#         user_data.industry is not None,
#         user_data.website is not None,
#         user_data.description is not None,
#         user_data.plan is not None
#     ]):
#         profile_update = {}
#         if user_data.companyName is not None:
#             profile_update["companyName"] = user_data.companyName
#         if user_data.industry is not None:
#             profile_update["industry"] = user_data.industry
#         if user_data.website is not None:
#             profile_update["website"] = user_data.website
#         if user_data.description is not None:
#             profile_update["description"] = user_data.description
#         if user_data.plan is not None:
#             profile_update["plan"] = user_data.plan

#         await prisma.companyprofile.update(
#             where={"userId": user_id},
#             data=profile_update
#         )

#     # Get updated user with profile
#     final_user = await prisma.user.find_unique(
#         where={"id": user_id},
#         include={
#             "creator": True,
#             "company": True,
#             "admin": True
#         }
#     )

#     return format_user_response(final_user)


@router.put("/{user_id}")
async def update_user(
    user_id: str, user_data: UpdateUserRequest, current_user=Depends(get_current_user)
):
    """Update user (full update)"""
    # Users can update their own profile, admins can update any profile
    if current_user.id != user_id:
        check_admin_permission(current_user)

    existing_user = await prisma.user.find_unique(where={"id": user_id})
    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Email/username conflict check (unchanged)
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

    # Prepare update data for user fields
    update_data = {}
    for field in [
        "email",
        "username",
        "firstName",
        "lastName",
        "status",
        "isVerified",
        "phone",
        "location",
    ]:
        value = getattr(user_data, field, None)
        if value is not None:
            update_data[field] = value

    # Password update (if you add password to UpdateUserRequest)
    if hasattr(user_data, "password") and user_data.password:
        update_data["password"] = hash_password(user_data.password)

    await prisma.user.update(
        where={"id": user_id},
        data=update_data,
        include={"creator": True, "company": True, "admin": True},
    )

    # Update profile data inside profileData (refactored)
    if user_data.profileData:
        profile_update = {}
        profile = user_data.profileData

        if existing_user.userType == UserType.CREATOR:
            # Assuming profile is of type UpdateCreatorProfileData
            if hasattr(profile, "bio") and profile.bio is not None:
                profile_update["bio"] = profile.bio
            if hasattr(profile, "niche") and profile.niche is not None:
                profile_update["niche"] = profile.niche
            if hasattr(profile, "plan") and profile.plan is not None:
                profile_update["plan"] = profile.plan

            if profile_update:
                await prisma.creatorprofile.update(
                    where={"userId": user_id}, data=profile_update
                )

        elif existing_user.userType == UserType.COMPANY:
            # Assuming profile is of type UpdateCompanyProfileData
            if hasattr(profile, "companyName") and profile.companyName is not None:
                profile_update["companyName"] = profile.companyName
            if hasattr(profile, "industry") and profile.industry is not None:
                profile_update["industry"] = profile.industry
            if hasattr(profile, "website") and profile.website is not None:
                profile_update["website"] = profile.website
            if hasattr(profile, "description") and profile.description is not None:
                profile_update["description"] = profile.description
            if hasattr(profile, "plan") and profile.plan is not None:
                profile_update["plan"] = profile.plan

            if profile_update:
                await prisma.companyprofile.update(
                    where={"userId": user_id}, data=profile_update
                )

        # Add similar handling for admin profile if needed

    final_user = await prisma.user.find_unique(
        where={"id": user_id}, include={"creator": True, "company": True, "admin": True}
    )

    return format_user_response(final_user)


@router.patch("/{user_id}", response_model=UserWithProfilesResponse)
async def patch_user(
    user_id: str, user_data: UpdateUserRequest, current_user=Depends(get_current_user)
):
    """Partially update user"""
    # Same logic as PUT but only updates provided fields
    return await update_user(user_id, user_data, current_user)


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user=Depends(get_current_user),
    hardDelete: bool = Query(False),
):
    """Delete user (soft delete by default)"""
    check_admin_permission(current_user, AdminRole.ADMIN)

    user = await prisma.user.find_unique(where={"id": user_id})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if hardDelete:
        # Hard delete - remove user and all related data
        await prisma.user.delete(where={"id": user_id})
    else:
        # Soft delete - deactivate account
        await prisma.user.update(
            where={"id": user_id},
            data={"status": AccountStatus.DEACTIVATED, "isActive": False},
        )

    return {"message": "User deleted successfully"}


@router.patch("/{user_id}/status", response_model=UserWithProfilesResponse)
async def update_user_status(
    user_id: str, status_data: UserStatusUpdate, current_user=Depends(get_current_user)
):
    """Update user status"""
    check_admin_permission(current_user, AdminRole.MODERATOR)

    user = await prisma.user.update(
        where={"id": user_id},
        data={"status": status_data.status},
        include={"creator": True, "company": True, "admin": True},
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return format_user_response(user)


@router.patch("/{user_id}/active", response_model=UserWithProfilesResponse)
async def toggle_user_active(
    user_id: str, active_data: UserActiveUpdate, current_user=Depends(get_current_user)
):
    """Activate/Deactivate user"""
    check_admin_permission(current_user, AdminRole.MODERATOR)

    user = await prisma.user.update(
        where={"id": user_id},
        data={"isActive": active_data.isActive},
        include={"creator": True, "company": True, "admin": True},
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return format_user_response(user)


@router.patch("/{user_id}/verify", response_model=UserWithProfilesResponse)
async def verify_user(user_id: str, current_user=Depends(get_current_user)):
    """Verify user email"""
    check_admin_permission(current_user, AdminRole.MODERATOR)

    user = await prisma.user.update(
        where={"id": user_id},
        data={"isVerified": True, "status": AccountStatus.ACTIVE},
        include={"creator": True, "company": True, "admin": True},
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return format_user_response(user)


@router.patch("/{user_id}/password")
async def change_user_password(
    user_id: str,
    password_data: ChangePasswordRequest,
    current_user=Depends(get_current_user),
):
    """Change user password (admin function)"""
    check_admin_permission(current_user, AdminRole.ADMIN)

    user = await prisma.user.find_unique(where={"id": user_id})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Hash new password
    hashed_password = hash_password(password_data.newPassword)

    # Update password
    await prisma.user.update(where={"id": user_id}, data={"password": hashed_password})

    # Invalidate all user sessions
    await prisma.usersession.delete_many(where={"userId": user_id})

    return {"message": "Password changed successfully"}


@router.post("/reset-password")
async def reset_password(reset_data: ResetPasswordRequest):
    """Reset password with token (public endpoint)"""
    try:
        import jwt

        payload = jwt.decode(
            reset_data.token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
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

    if not user or user.passwordResetToken != reset_data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token"
        )

    if user.passwordResetExpiresAt < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Reset token expired"
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


# ===== ROLE MANAGEMENT =====


@router.post("/{user_id}/roles", response_model=UserWithProfilesResponse)
async def assign_role(
    user_id: str, role_data: AssignRoleRequest, current_user=Depends(get_current_user)
):
    """Assign role to user"""
    check_admin_permission(current_user, AdminRole.ADMIN)

    # Check if user exists
    user = await prisma.user.find_unique(where={"id": user_id})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Check if role exists
    role = await prisma.role.find_unique(where={"id": role_data.roleId})
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )

    # Check if user already has this role
    existing_role = await prisma.userrole.find_first(
        where={"userId": user_id, "roleId": role_data.roleId}
    )

    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User already has this role"
        )

    # Assign role
    await prisma.userrole.create(data={"userId": user_id, "roleId": role_data.roleId})

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


@router.delete("/{user_id}/roles/{role_id}", response_model=UserWithProfilesResponse)
async def remove_role(
    user_id: str, role_id: str, current_user=Depends(get_current_user)
):
    """Remove role from user"""
    check_admin_permission(current_user, AdminRole.ADMIN)

    # Check if assignment exists
    user_role = await prisma.userrole.find_first(
        where={"userId": user_id, "roleId": role_id}
    )

    if not user_role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role assignment not found"
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


# ===== BULK OPERATIONS =====


@router.delete("/bulk-delete", response_model=BulkOperationResponse)
async def bulk_delete_users(
    delete_data: BulkDeleteRequest, current_user=Depends(get_current_user)
):
    """Bulk delete users"""
    check_admin_permission(current_user, AdminRole.ADMIN)

    successful = []
    failed = []

    for user_id in delete_data.userIds:
        try:
            user = await prisma.user.find_unique(where={"id": user_id})
            if not user:
                failed.append({"id": user_id, "error": "User not found"})
                continue

            if delete_data.hardDelete:
                await prisma.user.delete(where={"id": user_id})
            else:
                await prisma.user.update(
                    where={"id": user_id},
                    data={"status": AccountStatus.DEACTIVATED, "isActive": False},
                )

            successful.append(user_id)
        except Exception as e:
            failed.append({"id": user_id, "error": str(e)})

    return BulkOperationResponse(
        successful=successful, failed=failed, totalProcessed=len(delete_data.userIds)
    )


@router.patch("/bulk-update", response_model=BulkOperationResponse)
async def bulk_update_users(
    update_data: BulkUpdateRequest, current_user=Depends(get_current_user)
):
    """Bulk update users"""
    check_admin_permission(current_user, AdminRole.ADMIN)

    successful = []
    failed = []

    for user_id in update_data.userIds:
        try:
            user = await prisma.user.find_unique(where={"id": user_id})
            if not user:
                failed.append({"id": user_id, "error": "User not found"})
                continue

            # Prepare update data
            update_fields = {}
            for field in ["status", "isActive", "isVerified"]:
                value = getattr(update_data.updates, field, None)
                if value is not None:
                    update_fields[field] = value

            if update_fields:
                await prisma.user.update(where={"id": user_id}, data=update_fields)

            successful.append(user_id)
        except Exception as e:
            failed.append({"id": user_id, "error": str(e)})

    return BulkOperationResponse(
        successful=successful, failed=failed, totalProcessed=len(update_data.userIds)
    )
