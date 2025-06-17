from enum import Enum
from typing import List, Optional, Union, Literal
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


# === ENUMS ===

class UserType(str, Enum):
    CREATOR = 'CREATOR'
    COMPANY = 'COMPANY'
    ADMIN = 'ADMIN'


class AccountStatus(str, Enum):
    PENDING_VERIFICATION = 'PENDING_VERIFICATION'
    ACTIVE = 'ACTIVE'
    SUSPENDED = 'SUSPENDED'
    BANNED = 'BANNED'


class PlanType(str, Enum):
    FREE = 'FREE'
    BASIC = 'BASIC'
    PREMIUM = 'PREMIUM'
    ENTERPRISE = 'ENTERPRISE'


class AdminRole(str, Enum):
    SUPER_ADMIN = 'SUPER_ADMIN'
    ADMIN = 'ADMIN'
    MODERATOR = 'MODERATOR'


# === PROFILE SCHEMAS ===

class CreatorProfile(BaseModel):
    id: str
    userId: str
    plan: PlanType
    bio: Optional[str] = None
    niche: List[str]
    totalFollowers: int
    avgEngagement: float
    isVerified: bool
    createdAt: datetime
    updatedAt: datetime


class CompanyProfile(BaseModel):
    id: str
    userId: str
    companyName: str
    plan: PlanType
    industry: str
    website: Optional[str] = None
    description: Optional[str] = None
    logo: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime


class AdminProfile(BaseModel):
    id: str
    userId: str
    role: AdminRole
    createdAt: datetime
    updatedAt: datetime


# === ROLE MODELS ===

class RolePermission(BaseModel):
    id: str
    roleId: str
    permission: str


class Role(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    permissions: Optional[List[RolePermission]] = []
    users: Optional[List["UserRole"]] = []


class UserRole(BaseModel):
    id: str
    userId: str
    roleId: str
    role: Optional[Role] = None
    createdAt: datetime


# === SESSION MODEL ===

class UserSession(BaseModel):
    id: str
    userId: str
    token: str
    expiresAt: datetime
    createdAt: datetime


# === USER MODELS ===

class User(BaseModel):
    id: str
    email: EmailStr
    username: str
    firstName: str
    lastName: str
    avatar: Optional[str] = None
    userType: UserType
    isActive: bool
    isVerified: bool
    emailVerifiedAt: Optional[datetime] = None
    passwordResetToken: Optional[str] = None
    passwordResetExpiresAt: Optional[datetime] = None
    twoFactorEnabled: bool
    twoFactorSecret: Optional[str] = None
    status: AccountStatus
    createdAt: datetime
    deletedAt: Optional[datetime] = None
    updatedAt: datetime
    lastLoginAt: Optional[datetime] = None


class UserWithProfiles(User):
    creator: Optional[CreatorProfile] = None
    company: Optional[CompanyProfile] = None
    admin: Optional[AdminProfile] = None
    roles: Optional[List[UserRole]] = []
    sessions: Optional[List[UserSession]] = []


# === CREATE REQUEST MODELS ===

class CreateCreatorProfileData(BaseModel):
    plan: Optional[PlanType] = PlanType.FREE
    bio: Optional[str] = None
    niche: Optional[List[str]] = []


class CreateCompanyProfileData(BaseModel):
    companyName: str
    plan: Optional[PlanType] = PlanType.FREE
    industry: str
    website: Optional[str] = None
    description: Optional[str] = None
    logo: Optional[str] = None


class CreateAdminProfileData(BaseModel):
    role: Optional[AdminRole] = AdminRole.ADMIN


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    firstName: str
    lastName: str
    userType: UserType
    avatar: Optional[str] = None
    profileData: Optional[
        Union[CreateCreatorProfileData, CreateCompanyProfileData, CreateAdminProfileData]
    ] = None


# === UPDATE REQUEST MODELS ===

class UpdateCreatorProfileData(BaseModel):
    plan: Optional[PlanType] = None
    bio: Optional[str] = None
    niche: Optional[List[str]] = None
    totalFollowers: Optional[int] = None
    avgEngagement: Optional[float] = None
    isVerified: Optional[bool] = None


class UpdateCompanyProfileData(BaseModel):
    companyName: Optional[str] = None
    plan: Optional[PlanType] = None
    industry: Optional[str] = None
    website: Optional[str] = None
    description: Optional[str] = None
    logo: Optional[str] = None


class UpdateAdminProfileData(BaseModel):
    role: Optional[AdminRole] = None


class UpdateUserRequest(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    avatar: Optional[str] = None
    isActive: Optional[bool] = None
    status: Optional[AccountStatus] = None
    twoFactorEnabled: Optional[bool] = None
    profileData: Optional[
        Union[UpdateCreatorProfileData, UpdateCompanyProfileData, UpdateAdminProfileData]
    ] = None


# === SEARCH + PAGINATION ===

class UserSearchParams(BaseModel):
    page: Optional[int] = 1
    limit: Optional[int] = 20
    search: Optional[str] = None
    userType: Optional[UserType] = None
    status: Optional[AccountStatus] = None
    isActive: Optional[bool] = None
    isVerified: Optional[bool] = None
    plan: Optional[PlanType] = None
    sortBy: Optional[str] = "createdAt"
    sortOrder: Optional[str] = "desc"
    includeProfiles: Optional[bool] = True
    includeRoles: Optional[bool] = True


class Pagination(BaseModel):
    page: int
    limit: int
    total: int
    totalPages: int


class UserListResponse(BaseModel):
    users: List[UserWithProfiles]
    pagination: Pagination
    filters: Optional[UserSearchParams] = None


# === SECURITY ===

class ChangePasswordRequest(BaseModel):
    currentPassword: Optional[str] = None
    newPassword: str


class ResetPasswordRequest(BaseModel):
    token: str
    newPassword: str


class TwoFactorRequest(BaseModel):
    enabled: bool
    secret: Optional[str] = None


# === ROLE MGMT ===

class AssignRoleRequest(BaseModel):
    roleId: str


class CreateRoleRequest(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: Optional[List[str]] = []


class UpdateRoleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = []


# === BULK OPS ===

class BulkDeleteRequest(BaseModel):
    userIds: List[str]
    softDelete: Optional[bool] = True


class BulkUpdateEntry(BaseModel):
    id: str
    data: UpdateUserRequest


class BulkUpdateRequest(BaseModel):
    updates: List[BulkUpdateEntry]


class BulkOperationResponse(BaseModel):
    success: int
    failed: int
    errors: Optional[List[dict]] = None


# === ERROR RESPONSES ===

class APIError(BaseModel):
    message: str
    code: Optional[str] = None
    field: Optional[str] = None
    details: Optional[dict] = None


class ValidationError(APIError):
    code: Literal["VALIDATION_ERROR"] = "VALIDATION_ERROR"
    field: str



class UserResponse(BaseModel):
    user: User

class UserWithProfilesResponse(BaseModel):
    user: UserWithProfiles

class UserStatusUpdate(BaseModel):
    status: AccountStatus

class UserActiveUpdate(BaseModel):
    isActive: bool