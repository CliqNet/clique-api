# app/api/socials/posting.py

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import httpx
from datetime import datetime
from .social_platform_connector import SocialPlatformConnector, ConnectionStatus

router = APIRouter()

class PostContent(BaseModel):
    text: str
    platforms: List[str]  # ["INSTAGRAM", "FACEBOOK", "TWITTER"]
    media_urls: Optional[List[str]] = None
    schedule_time: Optional[datetime] = None

class PostResponse(BaseModel):
    success: bool
    results: Dict[str, Any]
    failed_platforms: List[str] = []

class SocialMediaPoster:
    def __init__(self, connector: SocialPlatformConnector):
        self.connector = connector
    
    async def post_to_platforms(self, user_id: str, content: PostContent) -> PostResponse:
        """Post content to multiple social platforms"""
        results = {}
        failed_platforms = []
        
        # Get user's connected accounts
        accounts = await self.connector.db.socialaccount.find_many(
            where={
                "userId": user_id,
                "platform": {"in": content.platforms},
                "isActive": True,
                "status": ConnectionStatus.CONNECTED.value
            }
        )
        
        if not accounts:
            raise HTTPException(400, "No connected accounts found for specified platforms")
        
        # Post to each platform
        for account in accounts:
            try:
                # Check if token is still valid
                if await self._is_token_expired(account):
                    refresh_success = await self.connector.refresh_token(account.id)
                    if not refresh_success:
                        failed_platforms.append(account.platform)
                        results[account.platform] = {"error": "Token expired and refresh failed"}
                        continue
                
                # Check rate limits
                if not await self.connector.check_rate_limit(account.id):
                    failed_platforms.append(account.platform)
                    results[account.platform] = {"error": "Rate limit exceeded"}
                    continue
                
                # Post to platform
                post_result = await self._post_to_platform(account, content)
                results[account.platform] = post_result
                
                # Record the API call
                await self.connector.record_api_call(account.id)
                
            except Exception as e:
                failed_platforms.append(account.platform)
                results[account.platform] = {"error": str(e)}
        
        return PostResponse(
            success=len(failed_platforms) == 0,
            results=results,
            failed_platforms=failed_platforms
        )
    
    async def _is_token_expired(self, account) -> bool:
        """Check if access token is expired"""
        if not account.expiresAt:
            return False
        return datetime.utcnow() >= account.expiresAt
    
    async def _post_to_platform(self, account, content: PostContent) -> Dict[str, Any]:
        """Post content to specific platform"""
        platform = account.platform
        
        if platform == "INSTAGRAM":
            return await self._post_to_instagram(account, content)
        elif platform == "FACEBOOK":
            return await self._post_to_facebook(account, content)
        elif platform == "TWITTER":
            return await self._post_to_twitter(account, content)
        elif platform == "LINKEDIN":
            return await self._post_to_linkedin(account, content)
        elif platform == "TIKTOK":
            return await self._post_to_tiktok(account, content)
        elif platform == "YOUTUBE":
            return await self._post_to_youtube(account, content)
        else:
            raise ValueError(f"Unsupported platform: {platform}")
    
    async def _post_to_instagram(self, account, content: PostContent) -> Dict[str, Any]:
        """Post to Instagram (requires media)"""
        if not content.media_urls:
            raise ValueError("Instagram posts require media")
        
        headers = {"Authorization": f"Bearer {account.accessToken}"}
        
        # Step 1: Create media container
        media_data = {
            "image_url": content.media_urls[0],
            "caption": content.text,
            "access_token": account.accessToken
        }
        
        async with httpx.AsyncClient() as client:
            # Create container
            container_response = await client.post(
                f"https://graph.facebook.com/v18.0/{account.platformId}/media",
                data=media_data
            )
            
            if container_response.status_code != 200:
                raise Exception(f"Failed to create media container: {container_response.text}")
            
            container_id = container_response.json()["id"]
            
            # Publish media
            publish_data = {
                "creation_id": container_id,
                "access_token": account.accessToken
            }
            
            publish_response = await client.post(
                f"https://graph.facebook.com/v18.0/{account.platformId}/media_publish",
                data=publish_data
            )
            
            if publish_response.status_code != 200:
                raise Exception(f"Failed to publish: {publish_response.text}")
            
            return {"post_id": publish_response.json()["id"], "platform": "INSTAGRAM"}
    
    async def _post_to_facebook(self, account, content: PostContent) -> Dict[str, Any]:
        """Post to Facebook Page"""
        post_data = {
            "message": content.text,
            "access_token": account.accessToken
        }
        
        if content.media_urls:
            post_data["link"] = content.media_urls[0]
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://graph.facebook.com/v18.0/{account.platformId}/posts",
                data=post_data
            )
            
            if response.status_code != 200:
                raise Exception(f"Facebook post failed: {response.text}")
            
            return {"post_id": response.json()["id"], "platform": "FACEBOOK"}
    
    async def _post_to_twitter(self, account, content: PostContent) -> Dict[str, Any]:
        """Post to Twitter/X"""
        headers = {
            "Authorization": f"Bearer {account.accessToken}",
            "Content-Type": "application/json"
        }
        
        tweet_data = {"text": content.text}
        
        # Handle media uploads if needed
        if content.media_urls:
            # Note: Twitter requires uploading media first, then referencing in tweet
            # This is a simplified version - you'd need to implement media upload
            pass
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.twitter.com/2/tweets",
                json=tweet_data,
                headers=headers
            )
            
            if response.status_code != 201:
                raise Exception(f"Twitter post failed: {response.text}")
            
            return {"post_id": response.json()["data"]["id"], "platform": "TWITTER"}
    
    async def _post_to_linkedin(self, account, content: PostContent) -> Dict[str, Any]:
        """Post to LinkedIn"""
        headers = {
            "Authorization": f"Bearer {account.accessToken}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }
        
        post_data = {
            "author": f"urn:li:person:{account.platformId}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": content.text},
                    "shareMediaCategory": "NONE"
                }
            },
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"}
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.linkedin.com/v2/ugcPosts",
                json=post_data,
                headers=headers
            )
            
            if response.status_code != 201:
                raise Exception(f"LinkedIn post failed: {response.text}")
            
            return {"post_id": response.json()["id"], "platform": "LINKEDIN"}
    
    async def _post_to_tiktok(self, account, content: PostContent) -> Dict[str, Any]:
        """Post to TikTok (simplified - usually requires video upload)"""
        # TikTok posting is complex and usually requires video files
        # This is a placeholder for the API structure
        raise NotImplementedError("TikTok posting requires video upload implementation")
    
    async def _post_to_youtube(self, account, content: PostContent) -> Dict[str, Any]:
        """Post to YouTube (Community posts or video upload)"""
        # YouTube posting varies - community posts vs video uploads
        # This is a placeholder for the API structure
        raise NotImplementedError("YouTube posting implementation depends on content type")

# FastAPI Routes
@router.post("/post", response_model=PostResponse)
async def create_social_post(
    content: PostContent,
    user_id: str,  # This would come from authentication middleware
    connector: SocialPlatformConnector = Depends()  # Dependency injection
):
    """Create a post across multiple social platforms"""
    poster = SocialMediaPoster(connector)
    return await poster.post_to_platforms(user_id, content)

@router.get("/accounts/{user_id}")
async def get_connected_accounts(
    user_id: str,
    connector: SocialPlatformConnector = Depends()
):
    """Get user's connected social accounts"""
    return await connector.get_user_accounts(user_id)

@router.post("/upload-media")
async def upload_media(file: UploadFile = File(...)):
    """Upload media file and return URL for posting"""
    # Implement your file upload logic (S3, Cloudinary, etc.)
    # Return the public URL to be used in posts
    pass