# app/api/users/user.py
from fastapi import APIRouter, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer
from prisma.enums import UserType, AdminRole

from app.models.user import (
    User,
    UserWithProfilesResponse,
    CreateUserRequest,
    UpdateUserRequest,
    UserListResponse,
    ChangePasswordRequest,
    ResetPasswordRequest,
    AssignRoleRequest,
    UserStatusUpdate,
    UserActiveUpdate,
)
from app.api.auth.auth import get_current_user
from app.services.user_service import UserService
from app.utils.user_utils import check_admin_permission

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
    return await UserService.get_users_by_type(UserType.CREATOR, page, limit)


@router.get("/companies", response_model=UserListResponse)
async def get_companies(
    # current_user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """Get list of all company users"""
    # check_admin_permission(current_user, AdminRole.ADMIN)
    return await UserService.get_users_by_type(UserType.COMPANY, page, limit)


@router.get("/admins", response_model=UserListResponse)
async def get_admins(
    # current_user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """Get list of all admin users"""
    # check_admin_permission(current_user, AdminRole.SUPER_ADMIN)
    return await UserService.get_users_by_type(UserType.ADMIN, page, limit)


# ===== USER MANAGEMENT ROUTES =====

@router.get("", response_model=UserListResponse)
async def get_users(
    # current_user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    includeProfiles: bool = Query(True),
    includeRoles: bool = Query(False),
):
    """Get all users with pagination and optional includes"""
    # check_admin_permission(current_user)
    return await UserService.get_all_users(page, limit, includeProfiles, includeRoles)


@router.get("/{user_id}", response_model=User)
async def get_user(
    user_id: str,
    # current_user=Depends(get_current_user),
    includeProfiles: bool = Query(True),
    includeRoles: bool = Query(False),
):
    """Get a specific user by ID"""
    # Users can view their own profile, admins can view any profile
    # if current_user.id != user_id:
    #     check_admin_permission(current_user)
    
    return await UserService.get_user_by_id(user_id, includeProfiles, includeRoles)


@router.get("/username/{username}", response_model=UserWithProfilesResponse)
async def get_user_by_username(
    username: str,
    current_user=Depends(get_current_user),
    includeProfiles: bool = Query(True),
):
    """Get user by username"""
    user = await UserService.get_user_by_username(username, includeProfiles)
    
    # Users can view their own profile, admins can view any profile
    if current_user.id != user.id:
        check_admin_permission(current_user)

    return user


@router.post("", response_model=UserWithProfilesResponse)
async def create_user(
    user_data: CreateUserRequest, 
    current_user=Depends(get_current_user)
):
    """Create a new user (admin only)"""
    check_admin_permission(current_user, AdminRole.ADMIN)
    return await UserService.create_user(user_data)


@router.put("/{user_id}")
async def update_user(
    user_id: str, 
    user_data: UpdateUserRequest, 
    current_user=Depends(get_current_user)
):
    """Update user (full update)"""
    # Users can update their own profile, admins can update any profile
    if current_user.id != user_id:
        check_admin_permission(current_user)

    return await UserService.update_user(user_id, user_data)


@router.patch("/{user_id}", response_model=UserWithProfilesResponse)
async def patch_user(
    user_id: str, 
    user_data: UpdateUserRequest, 
    current_user=Depends(get_current_user)
):
    """Partially update user"""
    # Users can update their own profile, admins can update any profile
    if current_user.id != user_id:
        check_admin_permission(current_user)

    return await UserService.update_user(user_id, user_data)


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user=Depends(get_current_user),
    hardDelete: bool = Query(False),
):
    """Delete user (soft delete by default)"""
    check_admin_permission(current_user, AdminRole.ADMIN)
    return await UserService.delete_user(user_id, hardDelete)


@router.patch("/{user_id}/status", response_model=UserWithProfilesResponse)
async def update_user_status(
    user_id: str, 
    status_data: UserStatusUpdate, 
    current_user=Depends(get_current_user)
):
    """Update user status"""
    check_admin_permission(current_user, AdminRole.MODERATOR)
    return await UserService.update_user_status(user_id, status_data)


@router.patch("/{user_id}/active", response_model=UserWithProfilesResponse)
async def toggle_user_active(
    user_id: str, 
    active_data: UserActiveUpdate, 
    current_user=Depends(get_current_user)
):
    """Activate/Deactivate user"""
    check_admin_permission(current_user, AdminRole.MODERATOR)
    return await UserService.toggle_user_active(user_id, active_data)


@router.patch("/{user_id}/verify", response_model=UserWithProfilesResponse)
async def verify_user(
    user_id: str, 
    current_user=Depends(get_current_user)
):
    """Verify user email"""
    check_admin_permission(current_user, AdminRole.MODERATOR)
    return await UserService.verify_user(user_id)


@router.patch("/{user_id}/password")
async def change_user_password(
    user_id: str,
    password_data: ChangePasswordRequest,
    current_user=Depends(get_current_user),
):
    """Change user password (admin function)"""
    check_admin_permission(current_user, AdminRole.ADMIN)
    return await UserService.change_user_password(user_id, password_data)


@router.post("/reset-password")
async def reset_password(reset_data: ResetPasswordRequest):
    """Reset password with token (public endpoint)"""
    return await UserService.reset_password(reset_data)


# ===== ROLE MANAGEMENT =====

@router.post("/{user_id}/roles", response_model=UserWithProfilesResponse)
async def assign_role(
    user_id: str, 
    role_data: AssignRoleRequest, 
    current_user=Depends(get_current_user)
):
    """Assign role to user"""
    check_admin_permission(current_user, AdminRole.ADMIN)
    return await UserService.assign_role(user_id, role_data)


@router.delete("/{user_id}/roles/{role_id}", response_model=UserWithProfilesResponse)
async def remove_role(
    user_id: str, 
    role_id: str, 
    current_user=Depends(get_current_user)
):
    """Remove role from user"""
    check_admin_permission(current_user, AdminRole.ADMIN)
    return await UserService.remove_role(user_id, role_id)