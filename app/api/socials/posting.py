# app/api/socials/posting.py

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import httpx
from datetime import datetime, timezone
from .social_platform_connector import SocialPlatformConnector, ConnectionStatus
from app.api.auth.auth import get_current_user
from app.models.user import User
from app.lib.prisma import prisma, Prisma

router = APIRouter()

# Import dependency functions from social_auth_routes to avoid duplication
from .social_auth_routes import get_database, get_connector

class PostRequest(BaseModel):
    account_id: str
    message: str
    media_urls: Optional[List[str]] = None
    schedule_time: Optional[datetime] = None

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

        # Use timezone-aware datetime for comparison
        now = datetime.now(timezone.utc)
        expires_at = account.expiresAt

        # If expiresAt is naive, make it aware
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        return now >= expires_at
    
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
        """Post to Facebook Page using FacebookDataFetcher"""
        print(f"DEBUG: Posting to Facebook page {account.platformId}")
        print(f"DEBUG: Message: {content.text}")
        print(f"DEBUG: Account type: {account.accountType}")

        # Use the existing FacebookDataFetcher for proper page posting
        from .facebook_data_fetcher import FacebookDataFetcher

        fb_fetcher = FacebookDataFetcher(self.connector.db)

        try:
            # Try to use stored page access token first
            page_access_token = getattr(account, 'pageAccessToken', None)
            user_access_token = getattr(account, 'userAccessToken', None) or account.accessToken

            print(f"DEBUG: Page access token available: {bool(page_access_token)}")
            print(f"DEBUG: User access token: {user_access_token[:20] if user_access_token else 'None'}...")

            # If no stored page access token, fetch it from user token
            if not page_access_token:
                try:
                    print("DEBUG: Attempting to fetch page access token from user token...")
                    pages = await fb_fetcher.get_user_pages(user_access_token)

                    print(f"DEBUG: Number of pages returned: {len(pages)}")
                    print(f"DEBUG: Looking for page ID: {account.platformId}")

                    # Find the page we want to post to
                    target_page = None
                    for i, page in enumerate(pages):
                        print(f"DEBUG: Page {i}: ID={page.get('id')}, Name={page.get('name')}, has_token={bool(page.get('access_token'))}")
                        if page.get("id") == account.platformId:
                            target_page = page
                            break

                    # If exact match not found, try to use the first page with an access token
                    if not target_page and pages:
                        print(f"DEBUG: Exact page ID match not found, trying first available page")
                        for page in pages:
                            if page.get("access_token"):
                                target_page = page
                                print(f"DEBUG: Using alternative page: ID={page.get('id')}, Name={page.get('name')}")

                                # Update the stored platform ID to match the actual page
                                await self.connector.db.socialaccount.update(
                                    where={"id": account.id},
                                    data={"platformId": page.get('id'), "username": page.get('name')}
                                )
                                print(f"DEBUG: Updated stored platform ID to {page.get('id')}")
                                break

                    if target_page and "access_token" in target_page:
                        page_access_token = target_page["access_token"]
                        print(f"DEBUG: Found page access token: {page_access_token[:20]}...")

                        # Store the page access token for future use
                        await self.connector.db.socialaccount.update(
                            where={"id": account.id},
                            data={"pageAccessToken": page_access_token}
                        )
                        print("DEBUG: Stored page access token for future use")
                    else:
                        print(f"DEBUG: Could not find page access token. Target page found: {target_page is not None}")
                        if target_page:
                            print(f"DEBUG: Target page keys: {list(target_page.keys())}")
                        available_pages = [f"ID={p.get('id')}, Name={p.get('name')}" for p in pages]
                        raise Exception(f"No page access token available. Available pages: {available_pages}")

                except Exception as token_error:
                    print(f"DEBUG: Failed to fetch page token: {token_error}")
                    raise Exception(f"Failed to get page access token: {token_error}")

            # Ensure we have a page access token
            if not page_access_token:
                raise Exception(f"No page access token available for Facebook page {account.platformId}")

            print(f"DEBUG: Using page access token: {page_access_token[:20]}...")

            # Get the current platform ID (in case it was updated)
            current_account = await self.connector.db.socialaccount.find_unique(
                where={"id": account.id}
            )
            current_platform_id = current_account.platformId if current_account else account.platformId

            # Use page access token and proper posting method
            result = await fb_fetcher.post_to_page(
                page_id=current_platform_id,
                page_access_token=page_access_token,
                message=content.text,
                link=content.media_urls[0] if content.media_urls else None
            )

            print(f"DEBUG: Facebook post successful! Result: {result}")
            return {"post_id": result.get("id"), "platform": "FACEBOOK", "response": result}

        except Exception as e:
            print(f"DEBUG: Facebook posting failed: {str(e)}")
            raise Exception(f"Facebook post failed: {str(e)}")
    
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
@router.post("/post")
async def create_social_post_by_account(
    post_request: PostRequest,
    current_user: User = Depends(get_current_user),
    connector: SocialPlatformConnector = Depends(get_connector)
):
    """Create a post to a specific social account"""
    try:
        # Get the social account
        account = await connector.db.socialaccount.find_unique(
            where={"id": post_request.account_id}
        )

        if not account:
            raise HTTPException(status_code=404, detail="Social account not found")

        # Verify account belongs to current user
        if account.userId != current_user.id:
            raise HTTPException(status_code=403, detail="Unauthorized access to account")

        # Check if account is connected
        if account.status != ConnectionStatus.CONNECTED.value:
            raise HTTPException(status_code=400, detail="Account is not connected")

        # Create poster and post
        poster = SocialMediaPoster(connector)

        # Convert to PostContent format for existing posting logic
        content = PostContent(
            text=post_request.message,
            platforms=[account.platform],
            media_urls=post_request.media_urls,
            schedule_time=post_request.schedule_time
        )

        result = await poster.post_to_platforms(current_user.id, content)

        print(f"DEBUG: Posting result: {result.success}")
        print(f"DEBUG: Results: {result.results}")
        print(f"DEBUG: Failed platforms: {result.failed_platforms}")

        return {
            "success": result.success,
            "message": "Post created successfully" if result.success else "Post failed",
            "results": result.results,
            "failed_platforms": result.failed_platforms
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create post: {str(e)}")

@router.post("/post/multi", response_model=PostResponse)
async def create_multi_platform_post(
    content: PostContent,
    current_user: User = Depends(get_current_user),
    connector: SocialPlatformConnector = Depends(get_connector)
):
    """Create a post across multiple social platforms"""
    poster = SocialMediaPoster(connector)
    return await poster.post_to_platforms(current_user.id, content)

@router.get("/accounts/{user_id}")
async def get_connected_accounts(
    user_id: str,
    connector: SocialPlatformConnector = Depends(get_connector)
):
    """Get user's connected social accounts"""
    return await connector.get_user_accounts(user_id)

@router.post("/upload-media")
async def upload_media(file: UploadFile = File(...)):
    """Upload media file and return URL for posting"""
    # Implement your file upload logic (S3, Cloudinary, etc.)
    # Return the public URL to be used in posts
    pass