# app/api/creators/creators_routes.py

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.lib.prisma import prisma
from app.api.auth.auth import get_current_user
from app.models.user import User


# Response models to match your React Native interface
class CreatorProfile(BaseModel):
    id: str
    username: str
    displayName: str  # This will come from firstName + lastName
    bio: Optional[str] = None
    avatar: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    categories: List[str] = []  # This will come from niche
    totalFollowers: int
    avgEngagement: float
    isVerified: bool
    connectionStatus: str = "NONE"  # NONE, PENDING, CONNECTED
    createdAt: str

    class Config:
        from_attributes = True


class CreatorsSearchResponse(BaseModel):
    creators: List[CreatorProfile]
    total: int
    hasMore: bool


class ConnectionRequest(BaseModel):
    creatorId: str
    message: Optional[str] = None


router = APIRouter(prefix="/creators", tags=["creators"])


@router.get("/search", response_model=CreatorsSearchResponse)
async def search_creators(
    query: Optional[str] = Query(None, description="Search query for creator names or usernames"),
    categories: Optional[str] = Query(None, description="Comma-separated categories to filter by"),
    location: Optional[str] = Query(None, description="Location filter"),
    verified_only: bool = Query(False, description="Show only verified creators"),
    min_followers: int = Query(0, description="Minimum follower count"),
    limit: int = Query(20, description="Number of results to return"),
    skip: int = Query(0, description="Number of results to skip"),
    current_user: User = Depends(get_current_user)
):
    """
    Search and discover creators for the network screen.
    Matches your React Native CreatorSearchFilters interface.
    """
    try:
        # Build filters
        filters = {
            "user": {
                "userType": "CREATOR",
                "status": "ACTIVE"
            },
            "totalFollowers": {"gte": min_followers}
        }

        # Add search query filter
        if query:
            filters["OR"] = [
                {"displayName": {"contains": query, "mode": "insensitive"}},
                {"user": {"username": {"contains": query, "mode": "insensitive"}}},
                {"bio": {"contains": query, "mode": "insensitive"}}
            ]

        # Add category filter (using niche field)
        if categories:
            category_list = [cat.strip().upper() for cat in categories.split(",")]
            filters["niche"] = {"hasSome": category_list}

        # Add location filter (location is in User model)
        if location:
            filters["user"]["location"] = {"contains": location, "mode": "insensitive"}

        # Add verification filter
        if verified_only:
            filters["isVerified"] = True

        # Exclude current user
        filters["userId"] = {"not": current_user.id}

        # Get total count
        total = await prisma.creatorprofile.count(where=filters)

        # Get creators with user data
        creator_profiles = await prisma.creatorprofile.find_many(
            where=filters,
            include={
                "user": True
            },
            order_by={"totalFollowers": "desc"},
            skip=skip,
            take=limit
        )

        # Format response
        creators = []
        for profile in creator_profiles:
            # Check connection status (you might want to implement this based on your connection system)
            connection_status = "NONE"  # TODO: Implement actual connection checking

            creators.append(CreatorProfile(
                id=profile.id,
                username=profile.user.username,
                displayName=f"{profile.user.firstName} {profile.user.lastName}",
                bio=profile.bio,
                avatar=profile.user.avatar,  # Avatar is in User model
                location=profile.user.location,  # Location is in User model
                website=None,  # Website not in current schema
                categories=profile.niche or [],  # Categories come from niche field
                totalFollowers=profile.totalFollowers or 0,
                avgEngagement=profile.avgEngagement or 0.0,
                isVerified=profile.isVerified or False,
                connectionStatus=connection_status,
                createdAt=profile.createdAt.isoformat()
            ))

        return CreatorsSearchResponse(
            creators=creators,
            total=total,
            hasMore=(skip + limit) < total
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search creators: {str(e)}")


@router.post("/connect")
async def send_connection_request(
    request: ConnectionRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Send a connection request to another creator.
    This is a placeholder - you might want to implement a proper connection system.
    """
    try:
        # Check if target creator exists
        target_creator = await prisma.creatorprofile.find_unique(
            where={"id": request.creatorId},
            include={"user": True}
        )

        if not target_creator:
            raise HTTPException(status_code=404, detail="Creator not found")

        if target_creator.userId == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot connect to yourself")

        # TODO: Implement actual connection request system
        # For now, we'll just return success
        # You might want to create a ConnectionRequest model and store these

        return {
            "success": True,
            "message": "Connection request sent successfully",
            "creatorId": request.creatorId
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send connection request: {str(e)}")


@router.get("/profile/{creator_id}", response_model=CreatorProfile)
async def get_creator_profile(
    creator_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get detailed creator profile"""
    try:
        creator_profile = await prisma.creatorprofile.find_unique(
            where={"id": creator_id},
            include={"user": True}
        )

        if not creator_profile:
            raise HTTPException(status_code=404, detail="Creator not found")

        # All profiles are public for now (you can add privacy settings later)

        return CreatorProfile(
            id=creator_profile.id,
            username=creator_profile.user.username,
            displayName=f"{creator_profile.user.firstName} {creator_profile.user.lastName}",
            bio=creator_profile.bio,
            avatar=creator_profile.user.avatar,
            location=creator_profile.user.location,
            website=None,  # Website not in current schema
            categories=creator_profile.niche or [],
            totalFollowers=creator_profile.totalFollowers or 0,
            avgEngagement=creator_profile.avgEngagement or 0.0,
            isVerified=creator_profile.isVerified or False,
            connectionStatus="NONE",  # TODO: Implement connection status checking
            createdAt=creator_profile.createdAt.isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get creator profile: {str(e)}")


@router.get("/featured", response_model=CreatorsSearchResponse)
async def get_featured_creators(
    limit: int = Query(10, description="Number of featured creators to return"),
    current_user: User = Depends(get_current_user)
):
    """Get featured South African creators for the network screen"""
    try:
        # Get top creators by followers, excluding current user
        creator_profiles = await prisma.creatorprofile.find_many(
            where={
                "user": {
                    "userType": "CREATOR",
                    "status": "ACTIVE",
                    "location": {"contains": "South Africa", "mode": "insensitive"}
                },
                "userId": {"not": current_user.id}
            },
            include={"user": True},
            order_by={"totalFollowers": "desc"},
            take=limit
        )

        creators = []
        for profile in creator_profiles:
            creators.append(CreatorProfile(
                id=profile.id,
                username=profile.user.username,
                displayName=f"{profile.user.firstName} {profile.user.lastName}",
                bio=profile.bio,
                avatar=profile.user.avatar,
                location=profile.user.location,
                website=None,
                categories=profile.niche or [],
                totalFollowers=profile.totalFollowers or 0,
                avgEngagement=profile.avgEngagement or 0.0,
                isVerified=profile.isVerified or False,
                connectionStatus="NONE",
                createdAt=profile.createdAt.isoformat()
            ))

        return CreatorsSearchResponse(
            creators=creators,
            total=len(creators),
            hasMore=False
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get featured creators: {str(e)}")