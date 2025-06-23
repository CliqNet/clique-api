# File: notification_service.py

from .websocket_manager import connection_manager
from typing import Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SocialAuthNotificationService:
    """Service for sending real-time notifications about social auth events"""
    
    @staticmethod
    async def notify_oauth_started(user_id: str, platform: str, oauth_url: str):
        """Notify user that OAuth process has started"""
        await connection_manager.send_to_user({
            "type": "oauth_started",
            "platform": platform,
            "oauth_url": oauth_url,
            "message": f"OAuth initiated for {platform}",
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

    @staticmethod
    async def notify_oauth_completed(user_id: str, platform: str, success: bool, account_data: Optional[Dict] = None):
        """Notify user about OAuth completion"""
        await connection_manager.send_to_user({
            "type": "oauth_completed",
            "platform": platform,
            "success": success,
            "account_data": account_data,
            "message": f"{'Successfully connected' if success else 'Failed to connect'} {platform}",
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

    @staticmethod
    async def notify_account_disconnected(user_id: str, platform: str, account_id: str):
        """Notify user about account disconnection"""
        await connection_manager.send_to_user({
            "type": "account_disconnected",
            "platform": platform,
            "account_id": account_id,
            "message": f"{platform} account disconnected",
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

    @staticmethod
    async def notify_token_refreshed(user_id: str, platform: str, account_id: str, success: bool):
        """Notify user about token refresh"""
        await connection_manager.send_to_user({
            "type": "token_refreshed",
            "platform": platform,
            "account_id": account_id,
            "success": success,
            "message": f"Token refresh {'successful' if success else 'failed'} for {platform}",
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

    @staticmethod
    async def notify_rate_limit_hit(user_id: str, platform: str, reset_time: Optional[datetime] = None):
        """Notify user about rate limit being hit"""
        await connection_manager.send_to_user({
            "type": "rate_limit_hit",
            "platform": platform,
            "reset_time": reset_time.isoformat() if reset_time else None,
            "message": f"Rate limit reached for {platform}",
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

    @staticmethod
    async def notify_webhook_received(user_id: str, platform: str, event_type: str, data: Dict):
        """Notify user about webhook events"""
        await connection_manager.send_to_user({
            "type": "webhook_event",
            "platform": platform,
            "event_type": event_type,
            "data": data,
            "message": f"Received {event_type} event from {platform}",
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

# Global notification service instance
notification_service = SocialAuthNotificationService()
