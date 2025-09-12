# app/api/socials/social_auth_routes.py

from fastapi import APIRouter, HTTPException, Query, Depends, WebSocket, BackgroundTasks, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional, List
from prisma import Prisma
from app.api.auth.auth import get_current_user
from app.models.user import User
from .social_platform_connector import SocialPlatformConnector, SocialPlatform
from .social_data_fetcher import SocialDataFetcher
from ...services.notification_service import notification_service
from ...services.websocket_manager import connection_manager
import os
import json
import jwt

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret")


# Pydantic models
class ConnectPlatformRequest(BaseModel):
    platform: str
    redirect_uri: str
    mobile_redirect_uri: Optional[str] = None  # For mobile apps to specify deep link


class OAuthCallbackRequest(BaseModel):
    code: str
    state: str
    redirect_uri: str
    error: Optional[str] = None


class SocialAccountResponse(BaseModel):
    id: str
    platform: str
    username: str
    displayName: Optional[str]
    avatar: Optional[str]
    followers: int
    following: int
    posts: int
    avgEngagement: float
    status: str
    connected_at: str
    last_sync: Optional[str]
    expires_at: Optional[str]
    sync_status: Optional[str]


class DisconnectAccountRequest(BaseModel):
    account_id: str

class SyncAccountRequest(BaseModel):
    account_id: str


class BulkSyncRequest(BaseModel):
    account_ids: Optional[List[str]] = None  # If None, sync all user's accounts


# Initialize router
router = APIRouter(prefix="/social", tags=["social-auth"])


# Database and connector dependencies
async def get_database():
    db = Prisma()
    await db.connect()
    try:
        yield db
    finally:
        await db.disconnect()


async def get_connector(db: Prisma = Depends(get_database)):
    connector = SocialPlatformConnector(db)
    await connector.initialize()
    return connector

async def get_data_fetcher(db: Prisma = Depends(get_database)):
    return SocialDataFetcher(db)



@router.post("/connect")
async def initiate_platform_connection(
    request: ConnectPlatformRequest,
    current_user=Depends(get_current_user),
    connector: SocialPlatformConnector = Depends(get_connector),
):
    """Initiate OAuth connection to a social platform"""
    try:
        platform = SocialPlatform(request.platform.upper())
        
        # Check if mobile redirect URI is provided
        if request.mobile_redirect_uri and request.mobile_redirect_uri.startswith(("exp://", "exps://", "myapp://", "clique://", "com.yourcompany.yourapp://")):
            print(f"DEBUG: Mobile OAuth initiated with redirect: {request.mobile_redirect_uri}")
            oauth_url = await connector.generate_oauth_url_with_mobile_redirect(
                platform=platform,
                user_id=current_user.id,
                redirect_uri=request.redirect_uri,  # Backend redirect URI
                mobile_redirect_uri=request.mobile_redirect_uri,  # Mobile deep link
            )
        else:
            oauth_url = await connector.generate_oauth_url(
                platform=platform,
                user_id=current_user.id,
                redirect_uri=request.redirect_uri,
            )

        # Notify via WebSocket
        await notification_service.notify_oauth_started(
            current_user.id, platform.value, oauth_url
        )

        return {"success": True, "oauth_url": oauth_url, "platform": platform.value}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection failed: {str(e)}")


@router.get("/callback")
async def oauth_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    error: Optional[str] = Query(None),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    connector: SocialPlatformConnector = Depends(get_connector),
    data_fetcher: SocialDataFetcher = Depends(get_data_fetcher),
):
    """Handle OAuth callback from social platforms"""
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")

    if error:
        # Handle mobile app error callback
        referer = str(request.headers.get("referer", ""))
        print(f"DEBUG: OAuth error, referer = '{referer}', error = '{error}'")
        
        if any(scheme in referer for scheme in ["exp://", "exps://", "myapp://", "clique://"]):
            if "exp://" in referer or "exps://" in referer:
                mobile_error_url = f"exp://192.168.0.22:8081/--/social/callback?error={error}"
            else:
                mobile_error_url = f"clique://auth/callback?error={error}"
            print(f"DEBUG: Mobile error redirect: {mobile_error_url}")
            return RedirectResponse(url=mobile_error_url, status_code=302)
        
        web_error_url = f"{frontend_url}/creator/accounts?error={error}"
        print(f"DEBUG: Web error redirect: {web_error_url}")
        return RedirectResponse(url=web_error_url, status_code=302)
    try:
        # Get redirect URI as fallback (for compatibility with existing oauth states)
        redirect_uri = f"{os.getenv('API_BASE_URL', 'http://127.0.0.1:8000')}/api/v1/social/callback"

        result = await connector.handle_oauth_callback(
            code=code, state=state, redirect_uri=redirect_uri
        )

        # Schedule background task to fetch user data
        background_tasks.add_task(
            sync_account_after_connection, 
            result.get("account_id")
        )

        # Notify via WebSocket about successful connection
        await notification_service.notify_oauth_completed(
            result.get("user_id"), result["platform"], True, result.get("account_data")
        )

        # Check if this is a mobile app callback (custom scheme)
        stored_redirect_uri = result.get("stored_redirect_uri", "")
        mobile_redirect_uri = result.get("mobile_redirect_uri")
        print(f"DEBUG: stored_redirect_uri = '{stored_redirect_uri}'")
        print(f"DEBUG: mobile_redirect_uri = '{mobile_redirect_uri}'")
        print(f"DEBUG: result keys = {list(result.keys())}")
        
        # Use mobile redirect URI from OAuth state if available
        if mobile_redirect_uri and mobile_redirect_uri.startswith(("exp://", "exps://", "myapp://", "clique://", "com.yourcompany.yourapp://")):
            # Mobile app callback - use the stored mobile redirect URI
            mobile_redirect_url = f"{mobile_redirect_uri.split('?')[0]}?success=true&platform={result['platform']}&account_id={result.get('account_id')}"
            print(f"DEBUG: Redirecting to mobile app (from state): {mobile_redirect_url}")
            return RedirectResponse(url=mobile_redirect_url)
        
        # Fallback: check for mobile app schemes in stored redirect URI or request headers
        is_mobile_app = False
        mobile_redirect_url = None
        
        if stored_redirect_uri.startswith(("exp://", "exps://", "myapp://", "clique://", "com.yourcompany.yourapp://")):
            is_mobile_app = True
            # Use the stored redirect URI but with success params
            mobile_redirect_url = f"{stored_redirect_uri.split('?')[0]}?success=true&platform={result['platform']}&account_id={result.get('account_id')}"
        
        # Also check referer header as fallback for mobile detection
        referer = str(request.headers.get("referer", ""))
        print(f"DEBUG: referer = '{referer}'")
        
        if not is_mobile_app and any(scheme in referer for scheme in ["exp://", "exps://", "myapp://", "clique://"]):
            is_mobile_app = True
            # For Expo apps, use exp:// scheme with success callback
            if "exp://" in referer or "exps://" in referer:
                mobile_redirect_url = f"{os.getenv('EXPO_URL', 'exp://192.168.0.22:8081')}/--/social/callback?success=true&platform=" + result['platform']
            else:
                mobile_redirect_url = f"clique://auth/callback?success=true&platform={result['platform']}&account_id={result.get('account_id')}"
        
        if is_mobile_app and mobile_redirect_url:
            print(f"DEBUG: Redirecting to mobile app (fallback): {mobile_redirect_url}")
            return RedirectResponse(url=mobile_redirect_url)
        else:
            # Web app callback - redirect to frontend
            frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
            web_redirect_url = f"{frontend_url}/creator/accounts?success=true&platform={result['platform']}"
            print(f"DEBUG: Redirecting to web app: {web_redirect_url}")
            return RedirectResponse(url=web_redirect_url)

    except ValueError as e:

        # Extract user_id from state if possible for notification
        try:
            import base64

            state_data = json.loads(base64.b64decode(state).decode())
            user_id = state_data.get("user_id")
            if user_id:
                await notification_service.notify_oauth_completed(
                    user_id, "UNKNOWN", False
                )
        except:
            pass

        # Handle mobile app error callback for value errors too
        error_redirect_url = None
        
        # Check referer for mobile app
        referer = str(request.headers.get("referer", ""))
        if any(scheme in referer for scheme in ["exp://", "exps://", "myapp://", "clique://"]):
            if "exp://" in referer or "exps://" in referer:
                error_redirect_url = "exp://192.168.0.22:8081/--/social/callback?error=" + str(e)
            else:
                error_redirect_url = f"clique://auth/callback?error={str(e)}"
        
        # Try to get redirect URI from state as fallback
        if not error_redirect_url:
            try:
                import base64
                state_data = json.loads(base64.b64decode(state).decode())
                redirect_uri = state_data.get("redirect_uri", "")
                if redirect_uri.startswith(("exp://", "exps://", "myapp://", "clique://", "com.yourcompany.yourapp://")):
                    error_redirect_url = f"{redirect_uri.split('?')[0]}?error={str(e)}"
            except:
                pass
        
        if error_redirect_url:
            print(f"DEBUG: Error redirect to mobile: {error_redirect_url}")
            return RedirectResponse(url=error_redirect_url)
        else:
            # Web app error callback
            frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
            web_error_url = f"{frontend_url}/creator/accounts?error={str(e)}"
            print(f"DEBUG: Error redirect to web: {web_error_url}")
            return RedirectResponse(url=web_error_url)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Callback processing failed: {str(e)}"
        )

async def sync_account_after_connection(account_id: str):
    """Background task to sync account data after successful connection"""
    try:
        # Wait a bit for the connection to be fully established
        import asyncio
        await asyncio.sleep(5)
        
        # Create new database connection for background task
        db = Prisma()
        await db.connect()
        
        try:
            # Import here to avoid circular imports
            from .social_data_fetcher import SocialDataFetcher
            data_fetcher = SocialDataFetcher(db)
            success = await data_fetcher.sync_account_data(account_id)
            print(f"Account {account_id} sync {'successful' if success else 'failed'}")
        finally:
            await db.disconnect()
            
    except Exception as e:
        print(f"Error syncing account {account_id}: {str(e)}")


@router.post("/sync")
async def sync_account(
    request: SyncAccountRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    data_fetcher: SocialDataFetcher = Depends(get_data_fetcher),
):
    """Manually sync a specific social media account"""
    try:
        # Verify account belongs to user
        db = data_fetcher.db
        account = await db.socialaccount.find_unique(
            where={"id": request.account_id}
        )
        
        if not account or account.userId != current_user.id:
            raise HTTPException(status_code=404, detail="Account not found")
        
        # Add sync task to background
        background_tasks.add_task(
            data_fetcher.sync_account_data, 
            request.account_id
        )
        
        return {
            "success": True, 
            "message": "Sync started", 
            "account_id": request.account_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sync failed: {str(e)}")


@router.get("/sync/status/{account_id}")
async def get_sync_status(
    account_id: str,
    current_user=Depends(get_current_user),
    db: Prisma = Depends(get_database),
):
    """Get sync status for a specific account"""
    try:
        account = await db.socialaccount.find_unique(
            where={"id": account_id}
        )
        
        if not account or account.userId != current_user.id:
            raise HTTPException(status_code=404, detail="Account not found")
        
        return {
            "account_id": account_id,
            "platform": account.platform,
            "sync_status": account.syncStatus,
            "last_sync": account.lastSyncAt.isoformat() if account.lastSyncAt else None,
            "next_sync": account.nextSyncAt.isoformat() if account.nextSyncAt else None,
            "sync_error": account.syncError,
            "followers": account.followers,
            "engagement": account.avgEngagement
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")


@router.get("/analytics/summary")
async def get_analytics_summary(
    current_user=Depends(get_current_user),
    db: Prisma = Depends(get_database),
):
    """Get analytics summary across all connected platforms"""
    try:
        accounts = await db.socialaccount.find_many(
            where={"userId": current_user.id, "isActive": True}
        )
        
        total_followers = sum(account.followers for account in accounts)
        total_following = sum(account.following for account in accounts)
        total_posts = sum(account.posts for account in accounts)
        avg_engagement = (
            sum(account.avgEngagement for account in accounts) / len(accounts)
            if accounts else 0
        )
        
        platform_breakdown = {}
        for account in accounts:
            platform_breakdown[account.platform] = {
                "followers": account.followers,
                "engagement": account.avgEngagement,
                "posts": account.posts,
                "last_sync": account.lastSyncAt.isoformat() if account.lastSyncAt else None
            }
        return {
            "summary": {
                "total_followers": total_followers,
                "total_following": total_following,
                "total_posts": total_posts,
                "avg_engagement": round(avg_engagement, 2),
                "connected_platforms": len(accounts)
            },
            "platforms": platform_breakdown,
            "last_updated": max(
                (account.lastSyncAt for account in accounts if account.lastSyncAt),
                default=None
            )
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analytics failed: {str(e)}")


# Background task endpoints (for cron jobs or scheduled tasks)
@router.post("/admin/sync-all")
async def admin_sync_all_accounts(
    background_tasks: BackgroundTasks,
    data_fetcher: SocialDataFetcher = Depends(get_data_fetcher),
):
    """Admin endpoint to sync all accounts that are due for sync"""
    try:
        background_tasks.add_task(data_fetcher.sync_all_accounts)
        return {"success": True, "message": "Bulk sync started for all due accounts"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Admin sync failed: {str(e)}")



# @router.get("/accounts")
# async def get_connected_accounts(
#     current_user=Depends(get_current_user),
#     connector: SocialPlatformConnector = Depends(get_connector),
# ) -> dict:
#     """Get all connected social accounts for the current user"""
#     try:
#         accounts = await connector.get_user_accounts(current_user.id)
#         return {"accounts": accounts}  # <-- wrap in object
#     except Exception as e:
#         raise HTTPException(
#             status_code=500, detail=f"Failed to fetch accounts: {str(e)}"
#         )

@router.get("/accounts")
async def get_connected_accounts(
    current_user=Depends(get_current_user),
    connector: SocialPlatformConnector = Depends(get_connector),
) -> dict:
    """Get all connected social accounts for the current user with detailed info"""
    try:
        # Get accounts with additional fields
        db = connector.db
        accounts = await db.socialaccount.find_many(
            where={"userId": current_user.id, "isActive": True},
            include={
                "creator": True,
                "company": True
            }
        )
        
        formatted_accounts = []
        for account in accounts:
            formatted_accounts.append({
                "id": account.id,
                "platform": account.platform,
                "username": account.username,
                "displayName": account.displayName,
                "avatar": account.avatar,
                "bio": account.bio,
                "website": account.website,
                "location": account.location,
                "followers": account.followers,
                "following": account.following,
                "posts": account.posts,
                "avgEngagement": account.avgEngagement,
                "status": account.status,
                "syncStatus": account.syncStatus,
                "connected_at": account.createdAt.isoformat(),
                "last_sync": account.lastSyncAt.isoformat() if account.lastSyncAt else None,
                "next_sync": account.nextSyncAt.isoformat() if account.nextSyncAt else None,
                "expires_at": account.expiresAt.isoformat() if account.expiresAt else None,
                "sync_error": account.syncError
            })
        return {"accounts": formatted_accounts}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch accounts: {str(e)}"
        )
    

@router.post("/disconnect")
async def disconnect_account(
    request: DisconnectAccountRequest,
    current_user=Depends(get_current_user),
    connector: SocialPlatformConnector = Depends(get_connector),
):
    """Disconnect a social media account"""
    try:
        success = await connector.disconnect_account(
            account_id=request.account_id, user_id=current_user.id
        )

        if not success:
            raise HTTPException(
                status_code=404, detail="Account not found or unauthorized"
            )

        return {"success": True, "message": "Account disconnected successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Disconnection failed: {str(e)}")


@router.post("/refresh/{account_id}")
async def refresh_account_token(
    account_id: str,
    current_user=Depends(get_current_user),
    connector: SocialPlatformConnector = Depends(get_connector),
):
    """Manually refresh access token for an account"""
    try:
        # Verify account belongs to user
        accounts = await connector.get_user_accounts(current_user["id"])
        account_ids = [acc["id"] for acc in accounts]

        if account_id not in account_ids:
            raise HTTPException(status_code=404, detail="Account not found")

        success = await connector.refresh_token(account_id)

        if success:
            return {"success": True, "message": "Token refreshed successfully"}
        else:
            return {"success": False, "message": "Token refresh failed"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")


@router.get("/platforms")
async def get_supported_platforms():
    """Get list of supported social platforms"""
    return {
        "platforms": [
            {
                "name": platform.value,
                "display_name": platform.value.title(),
                "supports_refresh": platform.value
                in ["FACEBOOK", "YOUTUBE", "LINKEDIN"],
            }
            for platform in SocialPlatform
        ]
    }


@router.get("/health/{account_id}")
async def check_account_health(
    account_id: str,
    current_user=Depends(get_current_user),
    connector: SocialPlatformConnector = Depends(get_connector),
):
    """Check the health status of a social media account"""
    try:
        # Verify account belongs to user
        accounts = await connector.get_user_accounts(current_user["id"])
        account = next((acc for acc in accounts if acc["id"] == account_id), None)

        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        # Check rate limit status
        can_make_calls = await connector.check_rate_limit(account_id)

        return {
            "account_id": account_id,
            "platform": account["platform"],
            "status": account["status"],
            "can_make_api_calls": can_make_calls,
            "last_sync": account["last_sync"],
            "token_expires": account["expires_at"],
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


# Background task for token refresh (run this periodically)
@router.post("/admin/refresh-expired-tokens")
async def refresh_expired_tokens(
    connector: SocialPlatformConnector = Depends(get_connector),
    db: Prisma = Depends(get_database),
):
    """Admin endpoint to refresh all expired tokens"""
    try:
        # Find accounts with expired tokens
        from datetime import datetime

        expired_accounts = await db.socialaccount.find_many(
            where={
                "isActive": True,
                "expiresAt": {"lt": datetime.utcnow()},
                "refreshToken": {"not": None},
            }
        )

        refreshed_count = 0
        failed_count = 0

        for account in expired_accounts:
            success = await connector.refresh_token(account.id)
            if success:
                refreshed_count += 1
            else:
                failed_count += 1

        return {
            "success": True,
            "refreshed": refreshed_count,
            "failed": failed_count,
            "total_processed": len(expired_accounts),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk refresh failed: {str(e)}")


@router.get("/websocket/status")
async def get_websocket_status(current_user=Depends(get_current_user)):
    """Get WebSocket connection status for current user"""
    return {
        "user_id": current_user["id"],
        "active_connections": connection_manager.get_user_connections_count(
            current_user["id"]
        ),
        "total_system_connections": connection_manager.get_total_connections(),
    }


async def get_current_user_ws(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket authentication using JWT"""
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            raise ValueError("user_id not found in token")
        return {"id": user_id}
    except jwt.ExpiredSignatureError:
        await websocket.close(code=4001, reason="Token expired")
    except jwt.InvalidTokenError:
        await websocket.close(code=4001, reason="Invalid token")
    except Exception:
        await websocket.close(code=4001, reason="Authentication failed")

    return None


# Facebook Page Management Endpoints

@router.get("/facebook/pages")
async def get_facebook_pages(
    current_user: User = Depends(get_current_user),
    db: Prisma = Depends(get_database)
):
    """Get all Facebook pages managed by the user"""
    # Get user's Facebook account
    facebook_account = await db.socialaccount.find_first(
        where={"userId": current_user.id, "platform": "FACEBOOK", "isActive": True}
    )
    
    if not facebook_account:
        raise HTTPException(status_code=404, detail="No Facebook account connected")
    
    try:
        from .facebook_data_fetcher import FacebookDataFetcher
        fb_fetcher = FacebookDataFetcher(db)
        pages = await fb_fetcher.get_user_pages(facebook_account.accessToken)
        
        return {
            "success": True,
            "pages": pages,
            "total": len(pages)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch pages: {str(e)}")


@router.post("/facebook/post")
async def post_to_facebook_page(
    request_data: dict,
    current_user: User = Depends(get_current_user),
    db: Prisma = Depends(get_database)
):
    """Post content to a Facebook page"""
    page_id = request_data.get("page_id")
    message = request_data.get("message")
    link = request_data.get("link")
    image_url = request_data.get("image_url")
    
    if not page_id or not message:
        raise HTTPException(status_code=400, detail="page_id and message are required")
    
    # Get user's Facebook account
    facebook_account = await db.socialaccount.find_first(
        where={"userId": current_user.id, "platform": "FACEBOOK", "isActive": True}
    )
    
    if not facebook_account:
        raise HTTPException(status_code=404, detail="No Facebook account connected")
    
    try:
        from .facebook_data_fetcher import FacebookDataFetcher
        fb_fetcher = FacebookDataFetcher(db)
        
        # Get pages to find the page access token
        pages = await fb_fetcher.get_user_pages(facebook_account.accessToken)
        page = next((p for p in pages if p["id"] == page_id), None)
        
        if not page:
            raise HTTPException(status_code=404, detail="Page not found or no access")
        
        # Post to the page
        result = await fb_fetcher.post_to_page(
            page_id=page_id,
            page_access_token=page["access_token"],
            message=message,
            link=link,
            image_url=image_url
        )
        
        return {
            "success": True,
            "post_id": result.get("id"),
            "message": "Post created successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to post: {str(e)}")


@router.post("/facebook/schedule")
async def schedule_facebook_post(
    request_data: dict,
    current_user: User = Depends(get_current_user),
    db: Prisma = Depends(get_database)
):
    """Schedule a post to Facebook page"""
    page_id = request_data.get("page_id")
    message = request_data.get("message")
    scheduled_time = request_data.get("scheduled_time")  # Unix timestamp
    link = request_data.get("link")
    image_url = request_data.get("image_url")
    
    if not page_id or not message or not scheduled_time:
        raise HTTPException(status_code=400, detail="page_id, message, and scheduled_time are required")
    
    # Get user's Facebook account
    facebook_account = await db.socialaccount.find_first(
        where={"userId": current_user.id, "platform": "FACEBOOK", "isActive": True}
    )
    
    if not facebook_account:
        raise HTTPException(status_code=404, detail="No Facebook account connected")
    
    try:
        from .facebook_data_fetcher import FacebookDataFetcher
        fb_fetcher = FacebookDataFetcher(db)
        
        # Get pages to find the page access token
        pages = await fb_fetcher.get_user_pages(facebook_account.accessToken)
        page = next((p for p in pages if p["id"] == page_id), None)
        
        if not page:
            raise HTTPException(status_code=404, detail="Page not found or no access")
        
        # Schedule the post
        result = await fb_fetcher.schedule_post(
            page_id=page_id,
            page_access_token=page["access_token"],
            message=message,
            scheduled_publish_time=int(scheduled_time),
            link=link,
            image_url=image_url
        )
        
        return {
            "success": True,
            "post_id": result.get("id"),
            "message": "Post scheduled successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to schedule post: {str(e)}")


@router.get("/facebook/posts/{page_id}")
async def get_facebook_page_posts(
    page_id: str,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Prisma = Depends(get_database)
):
    """Get recent posts from a Facebook page"""
    # Get user's Facebook account
    facebook_account = await db.socialaccount.find_first(
        where={"userId": current_user.id, "platform": "FACEBOOK", "isActive": True}
    )
    
    if not facebook_account:
        raise HTTPException(status_code=404, detail="No Facebook account connected")
    
    try:
        from .facebook_data_fetcher import FacebookDataFetcher
        fb_fetcher = FacebookDataFetcher(db)
        
        # Get pages to find the page access token
        pages = await fb_fetcher.get_user_pages(facebook_account.accessToken)
        page = next((p for p in pages if p["id"] == page_id), None)
        
        if not page:
            raise HTTPException(status_code=404, detail="Page not found or no access")
        
        # Get page posts
        posts = await fb_fetcher.get_page_posts(
            page_id=page_id,
            page_access_token=page["access_token"],
            limit=limit
        )
        
        return {
            "success": True,
            "posts": posts,
            "total": len(posts)
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch posts: {str(e)}")


@router.delete("/facebook/post/{post_id}")
async def delete_facebook_post(
    post_id: str,
    current_user: User = Depends(get_current_user),
    db: Prisma = Depends(get_database)
):
    """Delete a Facebook post"""
    # Get user's Facebook account
    facebook_account = await db.socialaccount.find_first(
        where={"userId": current_user.id, "platform": "FACEBOOK", "isActive": True}
    )
    
    if not facebook_account:
        raise HTTPException(status_code=404, detail="No Facebook account connected")
    
    try:
        from .facebook_data_fetcher import FacebookDataFetcher
        fb_fetcher = FacebookDataFetcher(db)
        
        # Get pages to find the appropriate page access token
        pages = await fb_fetcher.get_user_pages(facebook_account.accessToken)
        
        # Try to delete with each page token (since we don't know which page the post belongs to)
        for page in pages:
            try:
                success = await fb_fetcher.delete_post(post_id, page["access_token"])
                if success:
                    return {
                        "success": True,
                        "message": "Post deleted successfully"
                    }
            except:
                continue
        
        raise HTTPException(status_code=404, detail="Post not found or no permission to delete")
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to delete post: {str(e)}")
