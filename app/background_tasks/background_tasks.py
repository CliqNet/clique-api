# File: background_tasks.py

import asyncio
from datetime import datetime, timedelta
from ..services.notification_service import notification_service
from ..api.socials.social_auth_routes import get_database, get_connector
import logging

logger = logging.getLogger(__name__)


class BackgroundTaskManager:
    def __init__(self):
        self.running = False
        self.tasks = []

    async def start(self):
        """Start all background tasks"""
        if self.running:
            return

        self.running = True
        self.tasks = [
            asyncio.create_task(self.token_refresh_task()),
            asyncio.create_task(self.health_check_task()),
            asyncio.create_task(self.cleanup_task()),
        ]
        logger.info("Background tasks started")

    async def stop(self):
        """Stop all background tasks"""
        self.running = False
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        logger.info("Background tasks stopped")

    async def token_refresh_task(self):
        """Periodically refresh expiring tokens"""
        while self.running:
            try:
                async for db in get_database():
                    connector = await get_connector(db)

                    # Find tokens expiring in the next hour
                    expiring_soon = await db.socialaccount.find_many(
                        where={
                            "isActive": True,
                            "expiresAt": {
                                "gte": datetime.utcnow(),
                                "lte": datetime.utcnow() + timedelta(hours=1),
                            },
                            "refreshToken": {"not": None},
                        }
                    )

                    for account in expiring_soon:
                        success = await connector.refresh_token(account.id)
                        await notification_service.notify_token_refreshed(
                            account.userId, account.platform, account.id, success
                        )

                        if success:
                            logger.info(f"Refreshed token for account {account.id}")
                        else:
                            logger.warning(
                                f"Failed to refresh token for account {account.id}"
                            )

            except Exception as e:
                logger.error(f"Token refresh task error: {e}")

            # Run every 30 minutes
            await asyncio.sleep(1800)

    async def health_check_task(self):
        """Periodically check account health"""
        while self.running:
            try:
                async for db in get_database():
                    connector = await get_connector(db)

                    # Check all active accounts
                    active_accounts = await db.socialaccount.find_many(
                        where={"isActive": True}
                    )

                    for account in active_accounts:
                        can_make_calls = await connector.check_rate_limit(account.id)

                        if not can_make_calls:
                            await notification_service.notify_rate_limit_hit(
                                account.userId, account.platform
                            )

            except Exception as e:
                logger.error(f"Health check task error: {e}")

            # Run every 15 minutes
            await asyncio.sleep(900)

    async def cleanup_task(self):
        """Clean up old data"""
        while self.running:
            try:
                async for db in get_database():
                    # Clean up old webhooks (older than 7 days)
                    cutoff_date = datetime.utcnow() - timedelta(days=7)
                    await db.webhook.delete_many(
                        where={"processed": True, "createdAt": {"lt": cutoff_date}}
                    )

            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

            # Run daily
            await asyncio.sleep(86400)


# Global task manager
task_manager = BackgroundTaskManager()
