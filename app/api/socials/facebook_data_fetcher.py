# app/api/socials/facebook_data_fetcher.py

import httpx
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from prisma import Prisma


class FacebookDataFetcher:
    def __init__(self, db: Prisma):
        self.db = db
        self.base_url = "https://graph.facebook.com/v18.0"
    
    async def fetch_user_profile(self, access_token: str) -> Dict[str, Any]:
        """Fetch user profile data from Facebook"""
        fields = "id,name,picture.width(200).height(200),about,website,location,followers_count"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/me",
                params={
                    "fields": fields,
                    "access_token": access_token
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Facebook API error: {response.text}")
            
            data = response.json()
            
            return {
                "platform_id": data.get("id"),
                "display_name": data.get("name"),
                "avatar": data.get("picture", {}).get("data", {}).get("url"),
                "bio": data.get("about"),
                "website": data.get("website"),
                "location": data.get("location", {}).get("name") if data.get("location") else None,
                "followers": data.get("followers_count", 0)
            }
    
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