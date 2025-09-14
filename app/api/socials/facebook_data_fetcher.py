# app/api/socials/facebook_data_fetcher.py

import httpx
from datetime import datetime, timedelta
from typing import Dict, Any, List
from prisma import Prisma


class FacebookDataFetcher:
    def __init__(self, db: Prisma):
        self.db = db
        self.base_url = "https://graph.facebook.com/v18.0"
    
    async def fetch_user_profile(self, access_token: str) -> Dict[str, Any]:
        """Fetch user profile data from Facebook"""
        # For Facebook Users - personal profiles don't have followers_count
        user_fields = "id,name,email,picture.type(large),about,website,location"
        
        async with httpx.AsyncClient() as client:
            # Get user profile
            response = await client.get(
                f"{self.base_url}/me",
                params={
                    "fields": user_fields,
                    "access_token": access_token
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Facebook API error: {response.text}")
            
            user_data = response.json()
            
            # Try to get pages managed by this user
            pages_data = await self.fetch_user_pages(access_token)
            
            # If user has pages, use the first page's data, otherwise use user data
            if pages_data and len(pages_data) > 0:
                # Use page data for business accounts
                page = pages_data[0]  # Use first page
                return {
                    "platform_id": page.get("id"),
                    "display_name": page.get("name"),
                    "avatar": page.get("picture", {}).get("data", {}).get("url"),
                    "bio": page.get("about"),
                    "website": page.get("website"),
                    "location": page.get("location", {}).get("name") if page.get("location") else None,
                    "followers": page.get("fan_count", 0),
                    "account_type": "page"
                }
            else:
                # Personal profile - no follower count available
                return {
                    "platform_id": user_data.get("id"),
                    "display_name": user_data.get("name"),
                    "avatar": user_data.get("picture", {}).get("data", {}).get("url"),
                    "bio": user_data.get("about"),
                    "website": user_data.get("website"),
                    "location": user_data.get("location", {}).get("name") if user_data.get("location") else None,
                    "followers": 0,  # Personal profiles don't expose follower count
                    "account_type": "user"
                }
    
    async def fetch_user_pages(self, access_token: str) -> List[Dict[str, Any]]:
        """Fetch pages managed by the user"""
        page_fields = "id,name,fan_count,picture.type(large),category,about,website,location"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/me/accounts",
                params={
                    "fields": page_fields,
                    "access_token": access_token
                }
            )
            
            if response.status_code != 200:
                # If pages request fails, return empty list (user doesn't manage pages)
                return []
            
            data = response.json()
            return data.get("data", [])
    
    async def fetch_page_insights(self, page_id: str, access_token: str) -> Dict[str, Any]:
        """Fetch page insights for engagement metrics"""
        metrics = "page_fans,page_engaged_users,page_post_engagements"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/{page_id}/insights",
                params={
                    "metric": metrics,
                    "period": "day",
                    "since": (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"),
                    "until": datetime.now().strftime("%Y-%m-%d"),
                    "access_token": access_token
                }
            )
            
            if response.status_code != 200:
                return {"followers": 0, "engagement": 0.0}
            
            data = response.json()
            insights = {}
            
            for metric in data.get("data", []):
                metric_name = metric.get("name")
                values = metric.get("values", [])
                if values:
                    latest_value = values[-1].get("value", 0)
                    insights[metric_name] = latest_value
            
            return {
                "followers": insights.get("page_fans", 0),
                "engagement": insights.get("page_engaged_users", 0),
                "post_engagements": insights.get("page_post_engagements", 0)
            }
    
    async def sync_account_data(self, account_id: str) -> bool:
        """Sync account data with Facebook"""
        try:
            # Get account from database
            account = await self.db.socialaccount.find_unique(
                where={"id": account_id}
            )
            
            if not account or account.platform != "FACEBOOK":
                return False
            
            # Update sync status
            await self.db.socialaccount.update(
                where={"id": account_id},
                data={"syncStatus": "SYNCING"}
            )
            
            # Fetch profile data
            profile_data = await self.fetch_user_profile(account.accessToken)
            
            # Try to get page insights if it's a page
            insights_data = {}
            try:
                insights_data = await self.fetch_page_insights(
                    account.platformId, 
                    account.accessToken
                )
            except:
                # If insights fail, use profile followers
                insights_data = {"followers": profile_data.get("followers", 0)}
            
            # Update account with fetched data
            await self.db.socialaccount.update(
                where={"id": account_id},
                data={
                    "displayName": profile_data.get("display_name"),
                    "avatar": profile_data.get("avatar"),
                    "bio": profile_data.get("bio"),
                    "website": profile_data.get("website"),
                    "location": profile_data.get("location"),
                    "followers": insights_data.get("followers", 0),
                    "avgEngagement": self._calculate_engagement_rate(
                        insights_data.get("engagement", 0),
                        insights_data.get("followers", 1)
                    ),
                    "lastSyncAt": datetime.utcnow(),
                    "syncStatus": "COMPLETED",
                    "syncError": None,
                    "nextSyncAt": datetime.utcnow() + timedelta(hours=6)  # Next sync in 6 hours
                }
            )
            
            # Update creator profile total followers
            if account.creatorId:
                await self._update_creator_total_followers(account.creatorId)
            
            return True
            
        except Exception as e:
            # Update sync status with error
            await self.db.socialaccount.update(
                where={"id": account_id},
                data={
                    "syncStatus": "FAILED",
                    "syncError": str(e),
                    "nextSyncAt": datetime.utcnow() + timedelta(hours=1)  # Retry in 1 hour
                }
            )
            return False
    
    def _calculate_engagement_rate(self, engagement: int, followers: int) -> float:
        """Calculate engagement rate percentage"""
        if followers == 0:
            return 0.0
        return round((engagement / followers) * 100, 2)
    
    async def _update_creator_total_followers(self, creator_id: str):
        """Update creator's total followers across all platforms"""
        accounts = await self.db.socialaccount.find_many(
            where={"creatorId": creator_id, "isActive": True}
        )
        
        total_followers = sum(account.followers for account in accounts)
        avg_engagement = sum(account.avgEngagement for account in accounts) / len(accounts) if accounts else 0
        
        await self.db.creatorprofile.update(
            where={"id": creator_id},
            data={
                "totalFollowers": total_followers,
                "avgEngagement": round(avg_engagement, 2)
            }
        )
    
    async def get_user_pages(self, access_token: str) -> List[Dict[str, Any]]:
        """Get all pages managed by the user with their access tokens"""
        page_fields = "id,name,fan_count,picture.type(large),category,about,website,location,access_token"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/me/accounts",
                params={
                    "fields": page_fields,
                    "access_token": access_token
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Facebook API error getting pages: {response.text}")
            
            data = response.json()
            return data.get("data", [])
    
    async def post_to_page(self, page_id: str, page_access_token: str, message: str, 
                          link: str = None, image_url: str = None) -> Dict[str, Any]:
        """Post content to a Facebook page"""
        post_data = {
            "message": message,
            "access_token": page_access_token
        }
        
        if link:
            post_data["link"] = link
        
        async with httpx.AsyncClient() as client:
            if image_url:
                # Post with photo
                photo_data = {
                    "url": image_url,
                    "message": message,
                    "access_token": page_access_token
                }
                response = await client.post(
                    f"{self.base_url}/{page_id}/photos",
                    data=photo_data
                )
            else:
                # Post text/link
                response = await client.post(
                    f"{self.base_url}/{page_id}/feed",
                    data=post_data
                )
            
            if response.status_code != 200:
                raise Exception(f"Facebook posting error: {response.text}")
            
            return response.json()
    
    async def schedule_post(self, page_id: str, page_access_token: str, message: str, 
                           scheduled_publish_time: int, link: str = None, 
                           image_url: str = None) -> Dict[str, Any]:
        """Schedule a post to Facebook page"""
        post_data = {
            "message": message,
            "published": "false",  # Unpublished initially
            "scheduled_publish_time": scheduled_publish_time,  # Unix timestamp
            "access_token": page_access_token
        }
        
        if link:
            post_data["link"] = link
        
        async with httpx.AsyncClient() as client:
            if image_url:
                # Schedule photo post
                photo_data = {
                    "url": image_url,
                    "message": message,
                    "published": "false",
                    "scheduled_publish_time": scheduled_publish_time,
                    "access_token": page_access_token
                }
                response = await client.post(
                    f"{self.base_url}/{page_id}/photos",
                    data=photo_data
                )
            else:
                # Schedule text/link post
                response = await client.post(
                    f"{self.base_url}/{page_id}/feed",
                    data=post_data
                )
            
            if response.status_code != 200:
                raise Exception(f"Facebook scheduling error: {response.text}")
            
            return response.json()
    
    async def get_page_posts(self, page_id: str, page_access_token: str, 
                            limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent posts from a Facebook page"""
        fields = "id,message,created_time,likes.summary(true),comments.summary(true),shares"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/{page_id}/posts",
                params={
                    "fields": fields,
                    "limit": limit,
                    "access_token": page_access_token
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Facebook API error getting posts: {response.text}")
            
            data = response.json()
            return data.get("data", [])
    
    async def delete_post(self, post_id: str, page_access_token: str) -> bool:
        """Delete a Facebook page post"""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.base_url}/{post_id}",
                params={"access_token": page_access_token}
            )
            
            return response.status_code == 200