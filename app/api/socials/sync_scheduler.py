# app/services/sync_scheduler.py

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any
from prisma import Prisma
from app.api.socials.social_data_fetcher import SocialDataFetcher
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)


class SyncScheduler:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.db = None
        self.data_fetcher = None
        self.is_running = False
    
    async def initialize(self):
        """Initialize database connection and data fetcher"""
        self.db = Prisma()
        await self.db.connect()
        self.data_fetcher = SocialDataFetcher(self.db)
        
    async def start(self):
        """Start the scheduler with all sync jobs"""
        if self.is_running:
            return
            
        await self.initialize()
        
        # Schedule different sync intervals based on priority
        
        # High priority: Every 2 hours for accounts with high engagement
        self.scheduler.add_job(
            self.sync_high_priority_accounts,
            IntervalTrigger(hours=2),
            id="sync_high_priority",
            name="Sync High Priority Accounts",
            max_instances=1
        )
        
        # Medium priority: Every 6 hours for regular accounts
        self.scheduler.add_job(
            self.sync_regular_accounts,
            IntervalTrigger(hours=6),
            id="sync_regular",
            name="Sync Regular Accounts",
            max_instances=1
        )
        
        # Low priority: Daily sync for inactive accounts
        self.scheduler.add_job(
            self.sync_inactive_accounts,
            CronTrigger(hour=2, minute=0),  # 2 AM daily
            id="sync_inactive",
            name="Sync Inactive Accounts",
            max_instances=1
        )
        
        # Token refresh: Every hour
        self.scheduler.add_job(
            self.refresh_expiring_tokens,
            IntervalTrigger(hours=1),
            id="refresh_tokens",
            name="Refresh Expiring Tokens",
            max_instances=1
        )
        
        # Cleanup: Daily at 3 AM
        self.scheduler.add_job(
            self.cleanup_old_data,
            CronTrigger(hour=3, minute=0),
            id="cleanup",
            name="Cleanup Old Data",
            max_instances=1
        )
        
        # Health check: Every 30 minutes
        self.scheduler.add_job(
            self.health_check,
            IntervalTrigger(minutes=30),
            id="health_check",
            name="Health Check",
            max_instances=1
        )
        
        self.scheduler.start()
        self.is_running = True
        logger.info("Sync scheduler started with all jobs")
    
    async def stop(self):
        """Stop the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
        
        if self.db:
            await self.db.disconnect()
            
        self.is_running = False
        logger.info("Sync scheduler stopped")
    
    async def sync_high_priority_accounts(self):
        """Sync accounts with high engagement or premium users"""
        try:
            logger.info("Starting high priority account sync")
            
            # Get accounts with high engagement or premium users
            accounts = await self.db.socialaccount.find_many(
                where={
                    "isActive": True,
                    "status": "CONNECTED",
                    "OR": [
                        {"avgEngagement": {"gte": 5.0}},  # High engagement
                        {"creator": {"plan": {"in": ["PRO", "PREMIUM"]}}},  # Premium users
                        {"company": {"plan": {"in": ["PRO", "PREMIUM"]}}}
                    ]
                },
                include={"creator": True, "company": True}
            )
            
            results = await self._sync_accounts_batch(accounts, "high_priority")
            logger.info(f"High priority sync completed: {results}")
            
        except Exception as e:
            logger.error(f"High priority sync failed: {str(e)}")
    
    async def sync_regular_accounts(self):
        """Sync regular accounts that are due for sync"""
        try:
            logger.info("Starting regular account sync")
            
            now = datetime.utcnow()
            accounts = await self.db.socialaccount.find_many(
                where={
                    "isActive": True,
                    "status": "CONNECTED",
                    "OR": [
                        {"nextSyncAt": {"lte": now}},
                        {"nextSyncAt": None}
                    ],
                    "avgEngagement": {"lt": 5.0}  # Not high engagement
                },
                include={"creator": True, "company": True}
            )
            
            results = await self._sync_accounts_batch(accounts, "regular")
            logger.info(f"Regular sync completed: {results}")
            
        except Exception as e:
            logger.error(f"Regular sync failed: {str(e)}")
    
    async def sync_inactive_accounts(self):
        """Sync accounts that haven't been synced in a while"""
        try:
            logger.info("Starting inactive account sync")
            
            cutoff_date = datetime.utcnow() - timedelta(days=2)
            accounts = await self.db.socialaccount.find_many(
                where={
                    "isActive": True,
                    "status": "CONNECTED",
                    "OR": [
                        {"lastSyncAt": {"lte": cutoff_date}},
                        {"lastSyncAt": None}
                    ]
                },
                include={"creator": True, "company": True}
            )
            
            results = await self._sync_accounts_batch(accounts, "inactive")
            logger.info(f"Inactive sync completed: {results}")
            
        except Exception as e:
            logger.error(f"Inactive sync failed: {str(e)}")
    
    async def refresh_expiring_tokens(self):
        """Refresh tokens that are about to expire"""
        try:
            logger.info("Starting token refresh")
            
            # Get tokens expiring in the next 24 hours
            expiry_threshold = datetime.utcnow() + timedelta(hours=24)
            accounts = await self.db.socialaccount.find_many(
                where={
                    "isActive": True,
                    "refreshToken": {"not": None},
                    "expiresAt": {"lte": expiry_threshold}
                }
            )
            
            refreshed = 0
            failed = 0
            
            for account in accounts:
                try:
                    # You'll need to import the connector
                    from app.api.socials.social_platform_connector import SocialPlatformConnector
                    connector = SocialPlatformConnector(self.db)
                    await connector.initialize()
                    
                    success = await connector.refresh_token(account.id)
                    if success:
                        refreshed += 1
                    else:
                        failed += 1
                        
                except Exception as e:
                    logger.error(f"Failed to refresh token for account {account.id}: {str(e)}")
                    failed += 1
            
            logger.info(f"Token refresh completed: {refreshed} refreshed, {failed} failed")
            
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
    
    async def cleanup_old_data(self):
        """Clean up old sync data and logs"""
        try:
            logger.info("Starting cleanup")
            
            # Clean up old OAuth states (older than 1 hour)
            cutoff = datetime.utcnow() - timedelta(hours=1)
            deleted_states = await self.db.oauthstate.delete_many(
                where={"createdAt": {"lte": cutoff}}
            )
            
            # Reset error counts for accounts that have been working
            await self.db.socialaccount.update_many(
                where={
                    "errorCount": {"gt": 0},
                    "status": "CONNECTED",
                    "lastSyncAt": {"gte": datetime.utcnow() - timedelta(days=1)}
                },
                data={"errorCount": 0, "lastError": None}
            )
            
            logger.info(f"Cleanup completed: {deleted_states} OAuth states deleted")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")
    
    async def health_check(self):
        """Perform health checks on the system"""
        try:
            # Check database connection
            await self.db.user.count()
            
            # Check for accounts with persistent errors
            problematic_accounts = await self.db.socialaccount.find_many(
                where={
                    "isActive": True,
                    "errorCount": {"gte": 5}
                }
            )
            
            if problematic_accounts:
                logger.warning(f"Found {len(problematic_accounts)} accounts with persistent errors")
                
                # Disable accounts with too many errors
                for account in problematic_accounts:
                    if account.errorCount >= 10:
                        await self.db.socialaccount.update(
                            where={"id": account.id},
                            data={
                                "status": "PLATFORM_ERROR",
                                "statusUpdatedAt": datetime.utcnow()
                            }
                        )
                        logger.warning(f"Disabled account {account.id} due to persistent errors")
            
            # Log system stats
            total_accounts = await self.db.socialaccount.count(
                where={"isActive": True}
            )
            connected_accounts = await self.db.socialaccount.count(
                where={"isActive": True, "status": "CONNECTED"}
            )
            
            logger.info(f"Health check: {connected_accounts}/{total_accounts} accounts connected")
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
    
    async def _sync_accounts_batch(self, accounts, batch_type: str) -> Dict[str, int]:
        """Sync a batch of accounts with rate limiting"""
        results = {"success": 0, "failed": 0, "total": len(accounts)}
        
        # Process in smaller batches to avoid overwhelming APIs
        batch_size = 10
        for i in range(0, len(accounts), batch_size):
            batch = accounts[i:i + batch_size]
            
            # Process batch concurrently but with limits
            tasks = []
            for account in batch:
                task = asyncio.create_task(
                    self._sync_single_account(account.id)
                )
                tasks.append(task)
            
            # Wait for batch to complete
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    results["failed"] += 1
                    logger.error(f"Batch sync error: {str(result)}")
                elif result:
                    results["success"] += 1
                else:
                    results["failed"] += 1
            
            # Rate limiting: wait between batches
            if i + batch_size < len(accounts):
                await asyncio.sleep(2)  # 2 second delay between batches
        
        return results
    
    async def _sync_single_account(self, account_id: str) -> bool:
        """Sync a single account with error handling"""
        try:
            return await self.data_fetcher.sync_account_data(account_id)
        except Exception as e:
            logger.error(f"Failed to sync account {account_id}: {str(e)}")
            return False
    
    async def trigger_manual_sync(self, account_id: str) -> bool:
        """Manually trigger sync for a specific account"""
        try:
            return await self.data_fetcher.sync_account_data(account_id)
        except Exception as e:
            logger.error(f"Manual sync failed for account {account_id}: {str(e)}")
            return False
    
    async def get_scheduler_status(self) -> Dict[str, Any]:
        """Get current scheduler status and job info"""
        if not self.is_running:
            return {"status": "stopped", "jobs": []}
        
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger)
            })
        
        return {
            "status": "running",
            "jobs": jobs,
            "total_jobs": len(jobs)
        }


# Global scheduler instance
sync_scheduler = SyncScheduler()


# Startup and shutdown functions for FastAPI
async def start_scheduler():
    """Start the sync scheduler (call this in FastAPI startup)"""
    await sync_scheduler.start()


async def stop_scheduler():
    """Stop the sync scheduler (call this in FastAPI shutdown)"""
    await sync_scheduler.stop()
