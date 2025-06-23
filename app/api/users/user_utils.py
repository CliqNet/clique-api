from datetime import datetime
from pydantic import ValidationError
from typing import Optional
from fastapi import HTTPException, status
from prisma.enums import UserType, AdminRole
from app.models.user import ( UserWithProfiles, UserListResponse, Pagination)
from app.lib.prisma import prisma

# ===== UTILITY FUNCTIONS =====
def format_user_response(user, include_profiles=True, include_roles=False):
    """Format user response with optional profile and role data"""
    # print(user)
    # Base user data
    user_data = {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "firstName": user.firstName,
        "lastName": user.lastName,
        "userType": user.userType,
        "status": user.status,
        "isVerified": user.isVerified,
        "twoFactorEnabled": user.twoFactorEnabled,
        "isActive": user.isActive if hasattr(user, 'isActive') else True,
        "avatar": user.avatar,
        "lastLoginAt": user.lastLoginAt.isoformat() if user.lastLoginAt else None,
        "createdAt": user.createdAt.isoformat() if user.createdAt else None,
        "updatedAt": user.updatedAt.isoformat() if hasattr(user, 'updatedAt') and user.updatedAt else None,
    }
    
    # Add profiles if requested and available
    if include_profiles:
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
        elif user.userType == UserType.COMPANY:
            profile_data = {
                "role": "COMPANY",
                "companyName": user.company.companyName,
                "industry": user.company.industry,
                "website": user.company.website,
                "description": user.company.description,
                "plan": user.company.plan
            }
        elif user.userType == UserType.ADMIN:
            profile_data = {
                "role": user.admin.role,
            }
        
        user_data["profile"] = profile_data
    
    # Add roles if requested and available
    if include_roles and hasattr(user, 'roles') and user.roles:
        user_roles = []
        for user_role in user.roles:
            role = user_role.role
            user_roles.append({
                "id": role.id,
                "name": role.name,
                "description": role.description
            })
        user_data["roles"] = user_roles
    
    return user_data

def check_admin_permission(current_user, required_admin_role: Optional[AdminRole] = None):
    """Check if user has admin permissions"""
    if current_user.userType != UserType.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    if required_admin_role and hasattr(current_user, 'admin') and current_user.admin:
        if current_user.admin.role == AdminRole.SUPER_ADMIN:
            return True  # Super admin can do everything
        elif required_admin_role == AdminRole.ADMIN and current_user.admin.role in [AdminRole.ADMIN, AdminRole.SUPER_ADMIN]:
            return True
        elif required_admin_role == AdminRole.MODERATOR and current_user.admin.role in [AdminRole.MODERATOR, AdminRole.ADMIN, AdminRole.SUPER_ADMIN]:
            return True
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient admin privileges"
            )
    
    return True

async def fetch_users_by_type(
    user_type: str,
    page: int,
    limit: int
) -> UserListResponse:
    skip = (page - 1) * limit
    
    # Fetch users with all related data
    users = await prisma.user.find_many(
        where={"userType": user_type},
        skip=skip,
        take=limit,
        order={"createdAt": "desc"},
        include={
            "creator": True,
            "company": True,
            "admin": True,
            # "roles": True,
            "roles": {
                "include": {
                    "role": True  # Include the actual role data
                    
                }
            },
            "sessions": True
        }
    )
    
    # Get total count for pagination
    total = await prisma.user.count(where={"userType": user_type})
    
    # Convert User objects to UserWithProfiles
    users_with_profiles = []
    for user in users:
        user_dict = user.model_dump()
        
        # Handle roles data carefully
        if 'roles' in user_dict and user_dict['roles']:
            processed_roles = []
            for role_data in user_dict['roles']:
                # Add missing fields with defaults or skip if required
                if 'id' not in role_data:
                    role_data['id'] = f"{role_data.get('userId', '')}-{role_data.get('roleId', '')}"
                if 'createdAt' not in role_data:
                    role_data['createdAt'] = datetime.now()
                processed_roles.append(role_data)
            user_dict['roles'] = processed_roles
        
        try:
            user_with_profiles = UserWithProfiles(**user_dict)
            users_with_profiles.append(user_with_profiles)
        except ValidationError as e:
            print(f"Validation error for user {user_dict.get('id', 'unknown')}: {e}")
            # You might want to handle this differently - skip user, use defaults, etc.
            continue
    
    # Create pagination object
    pagination = Pagination(
        page=page,
        limit=limit,
        total=total,
        totalPages=(total + limit - 1) // limit  # Calculate total pages
    )
    
    return UserListResponse(
        users=users_with_profiles,
        pagination=pagination
    )
