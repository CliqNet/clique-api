# File: app/models/__init__.py

from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, EmailStr


# Enums matching Prisma schema
class UserType(str, Enum):
    CREATOR = "CREATOR"
    COMPANY = "COMPANY"
    ADMIN = "ADMIN"


class SocialPlatform(str, Enum):
    INSTAGRAM = "INSTAGRAM"
    FACEBOOK = "FACEBOOK"
    YOUTUBE = "YOUTUBE"
    TWITTER = "TWITTER"
    TIKTOK = "TIKTOK"
    LINKEDIN = "LINKEDIN"


class PostStatus(str, Enum):
    DRAFT = "DRAFT"
    SCHEDULED = "SCHEDULED"
    PUBLISHED = "PUBLISHED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CampaignStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class ConnectionStatus(str, Enum):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    DECLINED = "DECLINED"
    BLOCKED = "BLOCKED"


# Pydantic Models for API


# User Models
class UserBase(BaseModel):
    email: EmailStr
    username: str
    firstName: str
    lastName: str
    userType: UserType
    avatar: Optional[str] = None


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    avatar: Optional[str] = None


class UserResponse(UserBase):
    id: str
    isActive: bool
    isVerified: bool
    createdAt: datetime
    lastLoginAt: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    email: EmailStr
    password: str


# Creator Models
class CreatorProfileBase(BaseModel):
    bio: Optional[str] = None
    niche: List[str] = []


class CreatorProfileCreate(CreatorProfileBase):
    pass


class CreatorProfileUpdate(CreatorProfileBase):
    pass


class CreatorProfileResponse(CreatorProfileBase):
    id: str
    userId: str
    totalFollowers: int
    avgEngagement: float
    isVerified: bool
    createdAt: datetime

    class Config:
        from_attributes = True


# Social Account Models
class SocialAccountBase(BaseModel):
    platform: SocialPlatform
    username: str


class SocialAccountCreate(SocialAccountBase):
    platformId: str
    accessToken: str
    refreshToken: Optional[str] = None
    expiresAt: Optional[datetime] = None


class SocialAccountUpdate(BaseModel):
    username: Optional[str] = None
    accessToken: Optional[str] = None
    refreshToken: Optional[str] = None
    expiresAt: Optional[datetime] = None
    isActive: Optional[bool] = None


class SocialAccountResponse(SocialAccountBase):
    id: str
    creatorId: str
    isActive: bool
    createdAt: datetime

    class Config:
        from_attributes = True


# Post Models
class PostBase(BaseModel):
    content: str
    mediaUrls: List[str] = []
    scheduledAt: Optional[datetime] = None


class PostCreate(PostBase):
    platformIds: List[str]  # Social account IDs to post to


class PostUpdate(BaseModel):
    content: Optional[str] = None
    mediaUrls: Optional[List[str]] = None
    scheduledAt: Optional[datetime] = None
    status: Optional[PostStatus] = None


class PostResponse(PostBase):
    id: str
    creatorId: str
    status: PostStatus
    publishedAt: Optional[datetime] = None
    createdAt: datetime

    class Config:
        from_attributes = True


# Company Models
class CompanyProfileBase(BaseModel):
    companyName: str
    industry: str
    website: Optional[str] = None
    description: Optional[str] = None
    logo: Optional[str] = None


class CompanyProfileCreate(CompanyProfileBase):
    pass


class CompanyProfileUpdate(CompanyProfileBase):
    companyName: Optional[str] = None
    industry: Optional[str] = None


class CompanyProfileResponse(CompanyProfileBase):
    id: str
    userId: str
    createdAt: datetime

    class Config:
        from_attributes = True


# Campaign Models
class CampaignBase(BaseModel):
    name: str
    description: Optional[str] = None
    budget: float
    startDate: datetime
    endDate: datetime


class CampaignCreate(CampaignBase):
    folderId: Optional[str] = None


class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    budget: Optional[float] = None
    startDate: Optional[datetime] = None
    endDate: Optional[datetime] = None
    status: Optional[CampaignStatus] = None


class CampaignResponse(CampaignBase):
    id: str
    companyId: str
    status: CampaignStatus
    createdAt: datetime

    class Config:
        from_attributes = True


# Campaign Creator Models
class CampaignCreatorInvite(BaseModel):
    creatorId: str
    fee: float


class CampaignCreatorResponse(BaseModel):
    id: str
    campaignId: str
    creatorId: str
    fee: float
    status: str
    invitedAt: datetime
    acceptedAt: Optional[datetime] = None

    class Config:
        from_attributes = True


# Analytics Models
class CreatorAnalyticsResponse(BaseModel):
    id: str
    creatorId: str
    date: datetime
    followers: int
    engagement: float
    reach: int
    impressions: int
    profileViews: int

    class Config:
        from_attributes = True


class PostAnalyticsResponse(BaseModel):
    id: str
    postId: str
    platform: SocialPlatform
    likes: int
    comments: int
    shares: int
    views: int
    reach: int
    impressions: int

    class Config:
        from_attributes = True


class CampaignAnalyticsResponse(BaseModel):
    id: str
    campaignId: str
    date: datetime
    reach: int
    impressions: int
    engagement: float
    clicks: int
    conversions: int
    spend: float

    class Config:
        from_attributes = True


# Folder Models
class FolderBase(BaseModel):
    name: str
    description: Optional[str] = None


class FolderCreate(FolderBase):
    parentId: Optional[str] = None


class FolderUpdate(FolderBase):
    name: Optional[str] = None


class FolderResponse(FolderBase):
    id: str
    companyId: str
    parentId: Optional[str] = None
    createdAt: datetime

    class Config:
        from_attributes = True


# Connection Models
class ConnectionRequest(BaseModel):
    creatorId: str


class ConnectionResponse(BaseModel):
    id: str
    requesterId: str
    creatorId: str
    status: ConnectionStatus
    createdAt: datetime

    class Config:
        from_attributes = True


# Notification Models
class NotificationResponse(BaseModel):
    id: str
    type: str
    title: str
    message: str
    isRead: bool
    createdAt: datetime
    data: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
