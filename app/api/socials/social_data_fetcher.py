# app/api/socials/social_data_fetcher.py

import httpx
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from prisma import Prisma
from enum import Enum


class SocialDataFetcher:
    def __init__(self, db: Prisma):
        self.db = db
        self.platform_apis = {
            "FACEBOOK": "https://graph.facebook.com/v18.0",
            "INSTAGRAM": "https://graph.instagram.com",
            "YOUTUBE": "https://www.googleapis.com/youtube/v3",
            "TWITTER": "https://api.twitter.com/2",
            "LINKEDIN": "https://api.linkedin.com/v2",
            "TIKTOK": "https://open-api.tiktok.com"
        }
    
    async def sync_account_data(self, account_id: str) -> bool:
        """Main method to sync account data based on platform"""
        try:
            account = await self.db.socialaccount.find_unique(
                where={"id": account_id}
            )
            
            if not account or not account.isActive:
                return False
            
            # Update sync status
            await self.db.socialaccount.update(
                where={"id": account_id},
                data={"syncStatus": "SYNCING"}
            )
            
            # Route to appropriate platform fetcher
            platform_data = None
            if account.platform == "FACEBOOK":
                platform_data = await self._fetch_facebook_data(account)
            elif account.platform == "INSTAGRAM":
                platform_data = await self._fetch_instagram_data(account)
            elif account.platform == "YOUTUBE":
                platform_data = await self._fetch_youtube_data(account)
            elif account.platform == "TWITTER":
                platform_data = await self._fetch_twitter_data(account)
            elif account.platform == "LINKEDIN":
                platform_data = await self._fetch_linkedin_data(account)
            elif account.platform == "TIKTOK":
                platform_data = await self._fetch_tiktok_data(account)
            
            if not platform_data:
                raise Exception(f"No data fetcher for platform {account.platform}")
            
            # Update account with fetched data
            await self.db.socialaccount.update(
                where={"id": account_id},
                data={
                    **platform_data,
                    "lastSyncAt": datetime.utcnow(),
                    "syncStatus": "COMPLETED",
                    "syncError": None,
                    "nextSyncAt": datetime.utcnow() + timedelta(hours=6)
                }
            )
            
            # Update creator/company totals
            if account.creatorId:
                await self._update_creator_totals(account.creatorId)
            elif account.companyId:
                await self._update_company_totals(account.companyId)
            
            return True
            
        except Exception as e:
            await self.db.socialaccount.update(
                where={"id": account_id},
                data={
                    "syncStatus": "FAILED",
                    "syncError": str(e),
                    "nextSyncAt": datetime.utcnow() + timedelta(hours=1)
                }
            )
            return False
    
    async def _fetch_facebook_data(self, account) -> Dict[str, Any]:
        """Fetch Facebook/Meta data"""
        fields = "id,name,picture.width(200).height(200),about,website,location,followers_count"
        
        async with httpx.AsyncClient() as client:
            # Get basic profile
            response = await client.get(
                f"{self.platform_apis['FACEBOOK']}/me",
                params={
                    "fields": fields,
                    "access_token": account.accessToken
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Facebook API error: {response.text}")
            
            data = response.json()
            
            # Try to get page insights for engagement
            engagement_rate = 0.0
            try:
                insights_response = await client.get(
                    f"{self.platform_apis['FACEBOOK']}/{account.platformId}/insights",
                    params={
                        "metric": "page_engaged_users,page_fans",
                        "period": "day",
                        "access_token": account.accessToken
                    }
                )
                
                if insights_response.status_code == 200:
                    insights = insights_response.json()
                    # Calculate engagement rate from insights
                    engagement_rate = self._calculate_facebook_engagement(insights)
                    
            except:
                pass  # Use default 0.0 if insights fail

            print("In Facebook fetcher.")
            print("Data: ", data)
            
            return {
                "displayName": data.get("name"),
                "avatar": data.get("picture", {}).get("data", {}).get("url"),
                "bio": data.get("about"),
                "website": data.get("website"),
                "location": data.get("location", {}).get("name") if data.get("location") else None,
                "followers": data.get("followers_count", 0),
                "avgEngagement": engagement_rate
            }
    
    async def _fetch_instagram_data(self, account) -> Dict[str, Any]:
        """Fetch Instagram data"""
        fields = "id,username,account_type,media_count,followers_count,follows_count"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.platform_apis['INSTAGRAM']}/me",
                params={
                    "fields": fields,
                    "access_token": account.accessToken
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Instagram API error: {response.text}")
            
            data = response.json()
            
            return {
                "displayName": data.get("username"),
                "followers": data.get("followers_count", 0),
                "following": data.get("follows_count", 0),
                "posts": data.get("media_count", 0),
                "avgEngagement": await self._calculate_instagram_engagement(account, data.get("followers_count", 1))
            }
    
    async def _fetch_youtube_data(self, account) -> Dict[str, Any]:
        """Fetch YouTube data"""
        async with httpx.AsyncClient() as client:
            # Get channel statistics
            response = await client.get(
                f"{self.platform_apis['YOUTUBE']}/channels",
                params={
                    "part": "snippet,statistics",
                    "mine": "true",
                    "access_token": account.accessToken
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"YouTube API error: {response.text}")
            
            data = response.json()
            
            if not data.get("items"):
                raise Exception("No YouTube channel found")
            
            channel = data["items"][0]
            snippet = channel.get("snippet", {})
            stats = channel.get("statistics", {})
            
            return {
                "displayName": snippet.get("title"),
                "avatar": snippet.get("thumbnails", {}).get("default", {}).get("url"),
                "bio": snippet.get("description"),
                "followers": int(stats.get("subscriberCount", 0)),
                "posts": int(stats.get("videoCount", 0)),
                "avgEngagement": await self._calculate_youtube_engagement(account, int(stats.get("subscriberCount", 1)))
            }
    
    async def _fetch_twitter_data(self, account) -> Dict[str, Any]:
        """Fetch Twitter/X data"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.platform_apis['TWITTER']}/users/me",
                params={
                    "user.fields": "name,username,description,profile_image_url,location,website,public_metrics"
                },
                headers={"Authorization": f"Bearer {account.accessToken}"}
            )
            
            if response.status_code != 200:
                raise Exception(f"Twitter API error: {response.text}")
            
            data = response.json()
            user_data = data.get("data", {})
            metrics = user_data.get("public_metrics", {})
            
            return {
                "displayName": user_data.get("name"),
                "avatar": user_data.get("profile_image_url"),
                "bio": user_data.get("description"),
                "website": user_data.get("website"),
                "location": user_data.get("location"),
                "followers": metrics.get("followers_count", 0),
                "following": metrics.get("following_count", 0),
                "posts": metrics.get("tweet_count", 0),
                "avgEngagement": await self._calculate_twitter_engagement(account, metrics.get("followers_count", 1))
            }
    
    async def _fetch_linkedin_data(self, account) -> Dict[str, Any]:
        """Fetch LinkedIn data"""
        async with httpx.AsyncClient() as client:
            # Get basic profile
            response = await client.get(
                f"{self.platform_apis['LINKEDIN']}/people/~:(id,firstName,lastName,profilePicture)",
                headers={"Authorization": f"Bearer {account.accessToken}"}
            )
            
            if response.status_code != 200:
                raise Exception(f"LinkedIn API error: {response.text}")
            
            data = response.json()
            
            # LinkedIn doesn't provide follower count in basic API
            # You'd need to use LinkedIn Marketing API for that
            
            return {
                "displayName": f"{data.get('firstName', {}).get('localized', {}).get('en_US', '')} {data.get('lastName', {}).get('localized', {}).get('en_US', '')}",
                "avatar": data.get("profilePicture", {}).get("displayImage"),
                "followers": 0,  # Would need Marketing API access
                "avgEngagement": 0.0
            }
    
    async def _fetch_tiktok_data(self, account) -> Dict[str, Any]:
        """Fetch TikTok data"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.platform_apis['TIKTOK']}/user/info/",
                params={"access_token": account.accessToken}
            )
            
            if response.status_code != 200:
                raise Exception(f"TikTok API error: {response.text}")
            
            data = response.json()
            user_data = data.get("data", {}).get("user", {})
            
            return {
                "displayName": user_data.get("display_name"),
                "avatar": user_data.get("avatar_url"),
                "bio": user_data.get("bio_description"),
                "followers": user_data.get("follower_count", 0),
                "following": user_data.get("following_count", 0),
                "posts": user_data.get("video_count", 0),
                "avgEngagement": 0.0  # TikTok doesn't provide engagement metrics in basic API
            }
    
    async def _calculate_instagram_engagement(self, account, followers: int) -> float:
        """Calculate Instagram engagement rate"""
        try:
            async with httpx.AsyncClient() as client:
                # Get recent media
                response = await client.get(
                    f"{self.platform_apis['INSTAGRAM']}/me/media",
                    params={
                        "fields": "id,like_count,comments_count",
                        "limit": "10",
                        "access_token": account.accessToken
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    media_items = data.get("data", [])
                    
                    if media_items:
                        total_engagement = sum(
                            (item.get("like_count", 0) + item.get("comments_count", 0))
                            for item in media_items
                        )
                        avg_engagement = total_engagement / len(media_items)
                        return round((avg_engagement / followers) * 100, 2) if followers > 0 else 0.0
                        
        except:
            pass
        
        return 0.0
    
    async def _calculate_youtube_engagement(self, account, subscribers: int) -> float:
        """Calculate YouTube engagement rate"""
        try:
            async with httpx.AsyncClient() as client:
                # Get recent videos
                response = await client.get(
                    f"{self.platform_apis['YOUTUBE']}/search",
                    params={
                        "part": "id",
                        "forMine": "true",
                        "type": "video",
                        "order": "date",
                        "maxResults": "10",
                        "access_token": account.accessToken
                    }
                )
                
                if response.status_code == 200:
                    search_data = response.json()
                    video_ids = [item["id"]["videoId"] for item in search_data.get("items", [])]
                    
                    if video_ids:
                        # Get video statistics
                        stats_response = await client.get(
                            f"{self.platform_apis['YOUTUBE']}/videos",
                            params={
                                "part": "statistics",
                                "id": ",".join(video_ids),
                                "access_token": account.accessToken
                            }
                        )
                        
                        if stats_response.status_code == 200:
                            stats_data = stats_response.json()
                            total_engagement = 0
                            
                            for video in stats_data.get("items", []):
                                stats = video.get("statistics", {})
                                engagement = (
                                    int(stats.get("likeCount", 0)) +
                                    int(stats.get("commentCount", 0))
                                )
                                total_engagement += engagement
                            
                            if len(stats_data.get("items", [])) > 0:
                                avg_engagement = total_engagement / len(stats_data["items"])
                                return round((avg_engagement / subscribers) * 100, 2) if subscribers > 0 else 0.0
                            
        except:
            pass
        
        return 0.0
    
    async def _calculate_twitter_engagement(self, account, followers: int) -> float:
        """Calculate Twitter engagement rate"""
        # Twitter API v2 doesn't provide engagement metrics in free tier
        # You'd need Academic Research or Enterprise access
        return 0.0
    
    def _calculate_facebook_engagement(self, insights_data) -> float:
        """Calculate Facebook engagement rate from insights"""
        try:
            data = insights_data.get("data", [])
            engaged_users = 0
            fans = 1
            
            for metric in data:
                if metric.get("name") == "page_engaged_users":
                    values = metric.get("values", [])
                    if values:
                        engaged_users = values[-1].get("value", 0)
                elif metric.get("name") == "page_fans":
                    values = metric.get("values", [])
                    if values:
                        fans = max(values[-1].get("value", 1), 1)
            
            return round((engaged_users / fans) * 100, 2)
        except:
            return 0.0
    
    async def _update_creator_totals(self, creator_id: str):
        """Update creator's total followers and engagement across all platforms"""
        accounts = await self.db.socialaccount.find_many(
            where={"creatorId": creator_id, "isActive": True}
        )
        
        total_followers = sum(account.followers for account in accounts)
        avg_engagement = (
            sum(account.avgEngagement for account in accounts) / len(accounts)
            if accounts else 0
        )
        
        await self.db.creatorprofile.update(
            where={"id": creator_id},
            data={
                "totalFollowers": total_followers,
                "avgEngagement": round(avg_engagement, 2)
            }
        )
    
    async def _update_company_totals(self, company_id: str):
        """Update company's total followers across all platforms"""
        accounts = await self.db.socialaccount.find_many(
            where={"companyId": company_id, "isActive": True}
        )
        
        # You might want to add similar fields to CompanyProfile
        # For now, we'll just log the totals
        total_followers = sum(account.followers for account in accounts)
        print(f"Company {company_id} total followers: {total_followers}")
    
    async def sync_all_accounts(self) -> Dict[str, int]:
        """Sync all accounts that are due for sync"""
        now = datetime.utcnow()
        
        # Get accounts that need syncing
        accounts_to_sync = await self.db.socialaccount.find_many(
            where={
                "isActive": True,
                "status": "CONNECTED",
                "OR": [
                    {"nextSyncAt": {"lte": now}},
                    {"nextSyncAt": None}
                ]
            }
        )
        
        results = {"success": 0, "failed": 0, "total": len(accounts_to_sync)}
        
        for account in accounts_to_sync:
            success = await self.sync_account_data(account.id)
            if success:
                results["success"] += 1
            else:
                results["failed"] += 1
        
        return results
