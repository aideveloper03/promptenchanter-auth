"""
Authentication Middleware for External APIs
This module provides middleware functions that can be used by external APIs
to verify API keys and manage conversation limits.
"""

import asyncio
import json
import aiosqlite
from typing import Optional, Dict, Any, Callable
from fastapi import HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..db.database import Database
from ..security.auth import validate_ip_address, SecurityValidator
from ..core.config import settings

# Initialize database instance for middleware
middleware_db = Database()

class AuthMiddleware:
    """Authentication middleware for external API integration"""
    
    def __init__(self, db_path: str = "user_management.db"):
        self.db = Database(db_path)
    
    async def verify_api_key(self, api_key: str, client_ip: str = None) -> Dict[str, Any]:
        """
        Verify API key and return user information
        
        Args:
            api_key: The API key to verify
            client_ip: Client IP address for whitelist validation
            
        Returns:
            Dict containing user information and verification status
            
        Raises:
            HTTPException: If API key is invalid or limits exceeded
        """
        try:
            # Validate IP if whitelisting is enabled
            if client_ip and not validate_ip_address(client_ip):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="IP address not whitelisted"
                )
            
            # Validate API key format
            if not SecurityValidator.validate_api_key_format(api_key):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key format"
                )
            
            # Get user by API key
            user = await self.db.get_user_by_key(api_key)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key"
                )
            
            # Check if user is active
            if not user.get('is_active', True):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account is inactive"
                )
            
            # Check conversation limits
            limits = json.loads(user['limits'])
            if limits.get('conversation_limit', 0) <= 0:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Conversation limit exceeded. Limit resets every 24 hours."
                )
            
            return {
                "valid": True,
                "user": user,
                "remaining_conversations": limits.get('conversation_limit', 0)
            }
            
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Authentication failed: {str(e)}"
            )
    
    async def deduct_conversation_limit(self, api_key: str) -> bool:
        """
        Deduct one conversation from user's limit
        
        Args:
            api_key: The API key of the user
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            user = await self.db.get_user_by_key(api_key)
            if not user:
                return False
            
            limits = json.loads(user['limits'])
            if limits.get('conversation_limit', 0) <= 0:
                return False
            
            limits['conversation_limit'] -= 1
            return await self.db.update_user_limits(user['username'], limits)
            
        except Exception:
            return False
    
    async def log_message_async(self, message_data: Dict[str, Any]) -> bool:
        """
        Log a message asynchronously
        
        Args:
            message_data: Message data to log
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            log_id = await self.db.log_message(message_data)
            return log_id is not None
        except Exception:
            return False
    
    async def get_user_info(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        Get user information by API key
        
        Args:
            api_key: The API key
            
        Returns:
            Dict containing user information or None if not found
        """
        try:
            user = await self.db.get_user_by_key(api_key)
            if user:
                return {
                    "username": user['username'],
                    "email": user['email'],
                    "subscription_plan": user['subscription_plan'],
                    "limits": json.loads(user['limits']),
                    "credits": json.loads(user['credits']),
                    "access_rtype": json.loads(user['access_rtype']),
                    "level": user['level']
                }
            return None
        except Exception:
            return None

# Global middleware instance
auth_middleware = AuthMiddleware()

# FastAPI middleware functions
async def verify_api_key_middleware(request: Request, call_next):
    """
    FastAPI middleware to verify API keys
    This can be added to FastAPI apps using app.middleware()
    """
    # Skip verification for non-protected routes
    protected_paths = ["/api/", "/chat/", "/generate/"]
    if not any(request.url.path.startswith(path) for path in protected_paths):
        response = await call_next(request)
        return response
    
    # Extract API key from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header"
        )
    
    api_key = auth_header.split(" ")[1]
    client_ip = request.client.host
    
    # Verify API key
    try:
        verification_result = await auth_middleware.verify_api_key(api_key, client_ip)
        
        # Add user info to request state for use in route handlers
        request.state.user = verification_result["user"]
        request.state.remaining_conversations = verification_result["remaining_conversations"]
        
        # Process the request
        response = await call_next(request)
        
        # Deduct conversation limit after successful request
        await auth_middleware.deduct_conversation_limit(api_key)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Middleware error: {str(e)}"
        )

# Decorator for protecting individual routes
def require_api_key(func: Callable) -> Callable:
    """
    Decorator to require API key authentication for individual routes
    
    Usage:
        @require_api_key
        async def my_protected_route(request: Request):
            user = request.state.user
            return {"message": f"Hello {user['username']}"}
    """
    async def wrapper(*args, **kwargs):
        # Extract request object
        request = None
        for arg in args:
            if isinstance(arg, Request):
                request = arg
                break
        
        if not request:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Request object not found"
            )
        
        # Extract API key from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid authorization header"
            )
        
        api_key = auth_header.split(" ")[1]
        client_ip = request.client.host
        
        # Verify API key
        verification_result = await auth_middleware.verify_api_key(api_key, client_ip)
        
        # Add user info to request state
        request.state.user = verification_result["user"]
        request.state.remaining_conversations = verification_result["remaining_conversations"]
        
        # Call the original function
        result = await func(*args, **kwargs)
        
        # Deduct conversation limit after successful request
        await auth_middleware.deduct_conversation_limit(api_key)
        
        return result
    
    return wrapper

# Utility functions for external integration
class UserManagerClient:
    """
    Client class for external APIs to interact with user management system
    """
    
    def __init__(self, db_path: str = "user_management.db"):
        self.auth = AuthMiddleware(db_path)
    
    async def verify_user(self, api_key: str, client_ip: str = None) -> Dict[str, Any]:
        """Verify user and return user information"""
        return await self.auth.verify_api_key(api_key, client_ip)
    
    async def deduct_usage(self, api_key: str) -> bool:
        """Deduct one conversation from user's limit"""
        return await self.auth.deduct_conversation_limit(api_key)
    
    async def log_conversation(self, api_key: str, model: str, messages: list, research_model: bool = False) -> bool:
        """Log a conversation"""
        user = await self.auth.get_user_info(api_key)
        if not user:
            return False
        
        message_data = {
            'username': user['username'],
            'email': user['email'],
            'model': model,
            'messages': messages,
            'research_model': research_model
        }
        
        return await self.auth.log_message_async(message_data)
    
    async def get_user_limits(self, api_key: str) -> Optional[Dict[str, int]]:
        """Get user's current limits"""
        user_info = await self.auth.get_user_info(api_key)
        return user_info.get('limits') if user_info else None
    
    async def initialize(self):
        """Initialize the database connection"""
        await self.auth.db.connect()
        await self.auth.db.init_db()
    
    async def close(self):
        """Close the database connection"""
        await self.auth.db.disconnect()

# Example usage in an external FastAPI app:
"""
from user_management.middleware.auth_middleware import UserManagerClient

# Initialize the client
user_manager = UserManagerClient()

@app.on_event("startup")
async def startup():
    await user_manager.initialize()

@app.on_event("shutdown") 
async def shutdown():
    await user_manager.close()

@app.post("/api/chat")
async def chat_endpoint(request: Request, data: dict):
    # Get API key from headers
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing API key")
    
    api_key = auth_header.split(" ")[1]
    client_ip = request.client.host
    
    # Verify user
    try:
        user_info = await user_manager.verify_user(api_key, client_ip)
        
        # Process the chat request
        response = process_chat(data)
        
        # Log the conversation
        await user_manager.log_conversation(
            api_key, 
            data.get("model", "gpt-3.5-turbo"),
            data.get("messages", [])
        )
        
        # Usage is automatically deducted during verification
        return response
        
    except HTTPException:
        raise
"""