# app/api/socials/social_platform_connector.py

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List
from urllib.parse import urlencode
import httpx
from prisma import Prisma
from enum import Enum


class SocialPlatform(Enum):
    INSTAGRAM = "INSTAGRAM"
    FACEBOOK = "FACEBOOK"
    YOUTUBE = "YOUTUBE"
    TWITTER = "TWITTER"
    TIKTOK = "TIKTOK"
    LINKEDIN = "LINKEDIN"


class ConnectionStatus(Enum):
    CONNECTED = "CONNECTED"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    RATE_LIMITED = "RATE_LIMITED"
    PERMISSION_REVOKED = "PERMISSION_REVOKED"
    PLATFORM_ERROR = "PLATFORM_ERROR"
    MAINTENANCE = "MAINTENANCE"


class SocialPlatformConnector:
    def __init__(self, db: Prisma):
        self.db = db
        self.platform_configs = {}

    async def initialize(self):
        """Load platform configurations from database"""
        configs = await self.db.platformconfig.find_many()
        for config in configs:
            self.platform_configs[config.platform] = {
                "app_id": config.appId,
                "app_secret": config.appSecret,
                "api_version": config.apiVersion,
                "rate_limit_hour": config.rateLimitPerHour,
                "rate_limit_day": config.rateLimitPerDay,
                "is_active": config.isActive,
            }

    async def generate_oauth_url(
        self, platform: SocialPlatform, user_id: str, redirect_uri: str
    ) -> str:
        """Generate OAuth authorization URL for a platform"""
        state = secrets.token_urlsafe(32)

        print(f"Generated state: {state}")  # Debug line

        # Validate that state was generated
        if not state:
            raise ValueError("Failed to generate state token")
        try:

            oauth_state_record = await self.db.oauthstate.create(
                data={
                    "state": state,
                    "userId": user_id,
                    "platform": platform.value,
                }
            )

            print(f"Created OAuth state record: {oauth_state_record.id}")  # Debug line
        except Exception as e:
            print(f"Failed to create OAuth state: {e}")
            raise ValueError(f"Failed to store OAuth state: {str(e)}")

        config = self.platform_configs.get(platform.value)
        if not config or not config["is_active"]:
            raise ValueError(f"Platform {platform.value} is not configured or inactive")

        base_urls = {
            SocialPlatform.INSTAGRAM: "https://api.instagram.com/oauth/authorize",
            SocialPlatform.FACEBOOK: "https://www.facebook.com/v18.0/dialog/oauth",
            SocialPlatform.YOUTUBE: "https://accounts.google.com/oauth2/v2/auth",
            SocialPlatform.TWITTER: "https://twitter.com/i/oauth2/authorize",
            SocialPlatform.TIKTOK: "https://www.tiktok.com/auth/authorize",
            SocialPlatform.LINKEDIN: "https://www.linkedin.com/oauth/v2/authorization",
        }

        scopes = {
            SocialPlatform.INSTAGRAM: "user_profile,user_media",
            SocialPlatform.FACEBOOK: "pages_show_list,pages_read_engagement,instagram_basic",
            SocialPlatform.YOUTUBE: "https://www.googleapis.com/auth/youtube.readonly",
            SocialPlatform.TWITTER: "tweet.read,users.read,follows.read",
            SocialPlatform.TIKTOK: "user.info.basic,video.list",
            SocialPlatform.LINKEDIN: "r_liteprofile,r_emailaddress,w_member_social",
        }

        params = {
            "client_id": config["app_id"],
            "redirect_uri": redirect_uri,
            "scope": scopes[platform],
            "response_type": "code",
            "state": state,
        }

        if platform == SocialPlatform.TWITTER:
            params["code_challenge"] = self._generate_pkce_challenge()
            params["code_challenge_method"] = "S256"

        return f"{base_urls[platform]}?{urlencode(params)}"

    async def handle_oauth_callback(
        self, code: str, state: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Handle OAuth callback and exchange code for tokens"""
        print("ooooooooooooooooooooooooooooooooooo")
        # Validate state
        oauth_state = await self.db.oauthstate.find_unique(where={"state": state})
        if not oauth_state:
            raise ValueError("Invalid or expired state parameter")
        print("STATE STATE STATE STATE STATE")
        print("STATE: ", oauth_state)

        # if (datetime.utcnow() - oauth_state.createdAt) > timedelta(minutes=10):  # 10 minutes expiry
        #     await self.db.oauthstate.delete(where={'state': state})
        #     raise ValueError("State parameter expired")

        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        created_at = oauth_state.createdAt

        if (now - created_at) > timedelta(minutes=10):
            await self.db.oauthstate.delete(where={"state": state})
            raise ValueError("State parameter expired")

        print("DELETE state")

        # 3. Clean up state (delete after use)
        await self.db.oauthstate.delete(where={"state": state})
        print("deleted state")

        platform = SocialPlatform(oauth_state.platform)
        user_id = oauth_state.userId
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        # Exchange code for tokens
        token_data = await self._exchange_code_for_tokens(platform, code, redirect_uri)

        print("dododododododoododoododoodood")
        # Get user info from platform
        user_info = await self._get_platform_user_info(
            platform, token_data["access_token"]
        )

        print("555555555555555555")

        # Store or update social account
        social_account = await self._create_or_update_social_account(
            user_id, platform, token_data, user_info
        )

        print("after after after")

        return {
            "success": True,
            "platform": platform.value,
            "username": user_info.get("username"),
            # "account_id": str(social_account.id),
            "account_id": str(social_account.get("id")) if isinstance(social_account, dict) else str(social_account.id),        }

    async def _exchange_code_for_tokens(
        self, platform: SocialPlatform, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for access tokens"""
        config = self.platform_configs[platform.value]

        token_urls = {
            SocialPlatform.INSTAGRAM: "https://api.instagram.com/oauth/access_token",
            SocialPlatform.FACEBOOK: "https://graph.facebook.com/v18.0/oauth/access_token",
            SocialPlatform.YOUTUBE: "https://oauth2.googleapis.com/token",
            SocialPlatform.TWITTER: "https://api.twitter.com/2/oauth2/token",
            SocialPlatform.TIKTOK: "https://open-api.tiktok.com/oauth/access_token",
            SocialPlatform.LINKEDIN: "https://www.linkedin.com/oauth/v2/accessToken",
        }

        data = {
            "client_id": config["app_id"],
            "client_secret": config["app_secret"],
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient() as client:
            if platform in [SocialPlatform.INSTAGRAM, SocialPlatform.FACEBOOK]:
                response = await client.post(token_urls[platform], data=data)
            else:
                response = await client.post(
                    token_urls[platform],
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

            if response.status_code != 200:
                raise Exception(f"Token exchange failed: {response.text}")

            return response.json()

    async def _get_platform_user_info(
        self, platform: SocialPlatform, access_token: str
    ) -> Dict[str, Any]:
        """Get user information from the platform"""
        headers = {"Authorization": f"Bearer {access_token}"}

        user_info_urls = {
            SocialPlatform.INSTAGRAM: "https://graph.instagram.com/me?fields=id,username",
            SocialPlatform.FACEBOOK: "https://graph.facebook.com/me?fields=id,name",
            SocialPlatform.YOUTUBE: "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true",
            SocialPlatform.TWITTER: "https://api.twitter.com/2/users/me",
            SocialPlatform.TIKTOK: "https://open-api.tiktok.com/oauth/userinfo",
            SocialPlatform.LINKEDIN: "https://api.linkedin.com/v2/people/~:(id,firstName,lastName)",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(user_info_urls[platform], headers=headers)

            if response.status_code != 200:
                raise Exception(f"Failed to get user info: {response.text}")

            data = response.json()

            # Normalize response format
            if platform == SocialPlatform.YOUTUBE:
                if "items" in data and data["items"]:
                    item = data["items"][0]
                    return {
                        "platform_id": item["id"],
                        "username": item["snippet"]["title"],
                    }
            elif platform == SocialPlatform.LINKEDIN:
                return {
                    "platform_id": data["id"],
                    "username": f"{data['firstName']['localized']['en_US']} {data['lastName']['localized']['en_US']}",
                }
            else:
                return {
                    "platform_id": data.get("id"),
                    "username": data.get("username") or data.get("name"),
                }

    async def _create_or_update_social_account(
        self,
        user_id: str,
        platform: SocialPlatform,
        token_data: Dict[str, Any],
        user_info: Dict[str, Any],
    ) -> Any:
        """Create or update social account in database"""

        # Get user profile to determine if creator or company
        user = await self.db.user.find_unique(
            where={"id": user_id}, include={"creator": True, "company": True}
        )

        print("extracting id")
        creator_id = user.creator.id if user.creator else None
        company_id = user.company.id if user.company else None

        # Calculate token expiry
        expires_at = None
        if "expires_in" in token_data:
            expires_at = datetime.utcnow() + timedelta(
                seconds=int(token_data["expires_in"])
            )

        # Check if account already exists
        existing_account = await self.db.socialaccount.find_first(
            where={"userId": user_id, "platform": platform.value}
        )

        account_data = {
            "userId": user_id,
            "creatorId": creator_id,
            "companyId": company_id,
            "platform": platform.value,
            "platformId": user_info["platform_id"],
            "username": user_info["username"],
            "accessToken": token_data["access_token"],
            "refreshToken": token_data.get("refresh_token"),
            "tokenType": token_data.get("token_type", "Bearer"),
            "scope": token_data.get("scope"),
            "expiresAt": expires_at,
            "status": ConnectionStatus.CONNECTED.value,
            "statusUpdatedAt": datetime.utcnow(),
            "isActive": True,
            "lastRefreshed": datetime.utcnow(),
            "errorCount": 0,
            "lastError": None,
        }

        if existing_account:
            result = await self.db.socialaccount.update(
                where={"id": existing_account.id}, data=account_data
            )
        else:
            result = await self.db.socialaccount.create(data=account_data)

        return result.dict() if hasattr(result, "dict") else result

    async def refresh_token(self, account_id: str) -> bool:
        """Refresh expired access token"""
        account = await self.db.socialaccount.find_unique(where={"id": account_id})
        if not account or not account.refreshToken:
            return False

        try:
            platform = SocialPlatform(account.platform)
            config = self.platform_configs[platform.value]

            refresh_urls = {
                SocialPlatform.FACEBOOK: "https://graph.facebook.com/v18.0/oauth/access_token",
                SocialPlatform.YOUTUBE: "https://oauth2.googleapis.com/token",
                SocialPlatform.LINKEDIN: "https://www.linkedin.com/oauth/v2/accessToken",
            }

            if platform not in refresh_urls:
                return False  # Platform doesn't support token refresh

            data = {
                "client_id": config["app_id"],
                "client_secret": config["app_secret"],
                "refresh_token": account.refreshToken,
                "grant_type": "refresh_token",
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(refresh_urls[platform], data=data)

                if response.status_code == 200:
                    token_data = response.json()
                    expires_at = None
                    if "expires_in" in token_data:
                        expires_at = datetime.utcnow() + timedelta(
                            seconds=int(token_data["expires_in"])
                        )

                    await self.db.socialaccount.update(
                        where={"id": account_id},
                        data={
                            "accessToken": token_data["access_token"],
                            "refreshToken": token_data.get(
                                "refresh_token", account.refreshToken
                            ),
                            "expiresAt": expires_at,
                            "lastRefreshed": datetime.utcnow(),
                            "status": ConnectionStatus.CONNECTED.value,
                            "refreshAttempts": 0,
                            "errorCount": 0,
                        },
                    )
                    return True
                else:
                    await self._handle_refresh_error(account_id)
                    return False

        except Exception as e:
            await self._handle_refresh_error(account_id, str(e))
            return False

    async def _handle_refresh_error(self, account_id: str, error: str = None):
        """Handle token refresh errors"""
        await self.db.socialaccount.update(
            where={"id": account_id},
            data={
                "refreshAttempts": {"increment": 1},
                "errorCount": {"increment": 1},
                "lastError": error,
                "status": (
                    ConnectionStatus.TOKEN_EXPIRED.value
                    if not error
                    else ConnectionStatus.PLATFORM_ERROR.value
                ),
                "statusUpdatedAt": datetime.utcnow(),
            },
        )

    async def check_rate_limit(self, account_id: str) -> bool:
        """Check if account has exceeded rate limits"""
        account = await self.db.socialaccount.find_unique(where={"id": account_id})
        if not account:
            return False

        config = self.platform_configs.get(account.platform, {})
        hourly_limit = config.get("rate_limit_hour", 100)
        # daily_limit = config.get("rate_limit_day", 1000)

        now = datetime.utcnow()

        # Check hourly limit
        if account.lastApiCall and (now - account.lastApiCall).seconds < 3600:
            if account.dailyApiCalls >= hourly_limit:
                await self.db.socialaccount.update(
                    where={"id": account_id},
                    data={
                        "status": ConnectionStatus.RATE_LIMITED.value,
                        "statusUpdatedAt": now,
                    },
                )
                return False

        # Reset daily counter if needed
        if account.quotaResetAt and now >= account.quotaResetAt:
            await self.db.socialaccount.update(
                where={"id": account_id},
                data={"dailyApiCalls": 0, "quotaResetAt": now + timedelta(days=1)},
            )

        return True

    async def record_api_call(self, account_id: str):
        """Record an API call for rate limiting"""
        await self.db.socialaccount.update(
            where={"id": account_id},
            data={"dailyApiCalls": {"increment": 1}, "lastApiCall": datetime.utcnow()},
        )

    async def disconnect_account(self, account_id: str, user_id: str) -> bool:
        """Disconnect a social account"""
        account = await self.db.socialaccount.find_unique(where={"id": account_id})

        if not account or account.userId != user_id:
            return False

        # Revoke token on platform (if supported)
        try:
            await self._revoke_platform_token(account)
        except:
            pass  # Continue even if revocation fails

        # Soft delete or deactivate
        await self.db.socialaccount.update(
            where={"id": account_id},
            data={
                "isActive": False,
                "status": ConnectionStatus.PERMISSION_REVOKED.value,
                "statusUpdatedAt": datetime.utcnow(),
            },
        )

        return True

    async def _revoke_platform_token(self, account):
        """Revoke access token on the platform"""
        revoke_urls = {
            "FACEBOOK": f"https://graph.facebook.com/me/permissions?access_token={account.accessToken}",
            "YOUTUBE": f"https://oauth2.googleapis.com/revoke?token={account.accessToken}",
            "LINKEDIN": "https://api.linkedin.com/v2/oauth/revoke",
        }

        if account.platform in revoke_urls:
            async with httpx.AsyncClient() as client:
                if account.platform == "LINKEDIN":
                    await client.post(
                        revoke_urls[account.platform],
                        data={"token": account.accessToken},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                elif account.platform == "FACEBOOK":
                    await client.delete(revoke_urls[account.platform])
                else:
                    await client.post(revoke_urls[account.platform])

    def _generate_pkce_challenge(self) -> str:
        """Generate PKCE challenge for Twitter OAuth"""
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = hashlib.sha256(code_verifier.encode()).digest()
        return code_challenge.hex()

    async def get_user_accounts(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all connected social accounts for a user"""
        accounts = await self.db.socialaccount.find_many(
            where={"userId": user_id, "isActive": True}
        )

        return [
            {
                "id": account.id,
                "platform": account.platform,
                "username": account.username,
                "status": account.status,
                "connected_at": account.createdAt,
                "last_sync": account.lastApiCall,
                "expires_at": account.expiresAt,
            }
            for account in accounts
        ]
