# File: websocket_routes.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from ...services.websocket_manager import connection_manager
from ..socials.social_auth_routes import get_current_user_ws, get_connector
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

router = APIRouter()

async def get_current_user_ws(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket authentication - replace with your actual auth logic"""
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return None
    
    # This would typically validate JWT token
    # For demo purposes, extracting user_id from token
    try:
        # Replace with actual token validation
        user_id = token  # Simplified - in reality, decode JWT
        return {"id": user_id}
    except Exception:
        await websocket.close(code=4001, reason="Invalid authentication")
        return None

@router.websocket("/ws/social-auth/{user_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    user_id: str,
    token: Optional[str] = Query(None)
):
    """Main WebSocket endpoint for social authentication updates"""
    
    # Authenticate user
    current_user = await get_current_user_ws(websocket, token)
    if not current_user or current_user["id"] != user_id:
        return
    
    try:
        await connection_manager.connect(websocket, user_id)
        
        while True:
            # Receive messages from client
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                await handle_websocket_message(websocket, user_id, message)
            except json.JSONDecodeError:
                await connection_manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON format"
                }, websocket)
                
    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        connection_manager.disconnect(websocket)

async def handle_websocket_message(websocket: WebSocket, user_id: str, message: Dict):
    """Handle incoming WebSocket messages from clients"""
    message_type = message.get("type")
    
    if message_type == "ping":
        await connection_manager.send_personal_message({
            "type": "pong",
            "timestamp": datetime.utcnow().isoformat()
        }, websocket)
        
    elif message_type == "get_accounts_status":
        # Get real-time account status
        try:
            from ..socials.social_auth_routes import get_database, get_connector
            async for db in get_database():
                connector = await get_connector(db)
                accounts = await connector.get_user_accounts(user_id)
                
                await connection_manager.send_personal_message({
                    "type": "accounts_status",
                    "data": accounts,
                    "timestamp": datetime.utcnow().isoformat()
                }, websocket)
        except Exception as e:
            await connection_manager.send_personal_message({
                "type": "error",
                "message": f"Failed to get accounts: {str(e)}"
            }, websocket)
            
    elif message_type == "subscribe_to_updates":
        # Client wants to subscribe to specific updates
        update_types = message.get("updates", [])
        await connection_manager.send_personal_message({
            "type": "subscription_confirmed",
            "subscribed_to": update_types,
            "message": f"Subscribed to {len(update_types)} update types"
        }, websocket)
        
    else:
        await connection_manager.send_personal_message({
            "type": "error",
            "message": f"Unknown message type: {message_type}"
        }, websocket)
