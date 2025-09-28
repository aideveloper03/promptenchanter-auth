import time
import asyncio
from typing import Callable, Dict, Any, Optional
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from ..cache.redis_manager import redis_manager
from ..db.enhanced_database import enhanced_database
from ..security.auth import verify_token, SecurityValidator
import logging

logger = logging.getLogger(__name__)

class PerformanceMiddleware(BaseHTTPMiddleware):
    """Enhanced middleware for performance optimization and caching"""
    
    def __init__(self, app, enable_caching: bool = True, enable_rate_limiting: bool = True):
        super().__init__(app)
        self.enable_caching = enable_caching
        self.enable_rate_limiting = enable_rate_limiting
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        # Performance tracking
        request.state.start_time = start_time
        
        try:
            # Rate limiting
            if self.enable_rate_limiting and await self._check_rate_limit(request):
                return self._rate_limit_response()
            
            # API key caching for performance
            if self.enable_caching:
                await self._handle_api_key_caching(request)
            
            # Process request
            response = await call_next(request)
            
            # Add performance headers
            response_time = time.time() - start_time
            response.headers["X-Response-Time"] = f"{response_time:.3f}s"
            response.headers["X-Process-ID"] = str(asyncio.current_task())
            
            # Log API usage for monitoring
            await self._log_api_usage(request, response, response_time)
            
            return response
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Request failed after {response_time:.3f}s: {e}")
            
            # Log error
            await self._log_api_usage(request, None, response_time, error=str(e))
            
            raise
    
    async def _check_rate_limit(self, request: Request) -> bool:
        """Enhanced rate limiting with Redis"""
        client_ip = request.client.host
        
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/docs", "/openapi.json"]:
            return False
        
        # Different limits for different endpoints
        if request.url.path.startswith("/api/v1/auth/login"):
            # Stricter limits for login endpoints
            return await redis_manager.is_rate_limited(
                f"login_rate:{client_ip}", 
                limit=5, 
                window=300  # 5 requests per 5 minutes
            )
        elif request.url.path.startswith("/api/v1/"):
            # General API rate limiting
            return await redis_manager.is_rate_limited(
                f"api_rate:{client_ip}", 
                limit=60, 
                window=60  # 60 requests per minute
            )
        
        return False
    
    def _rate_limit_response(self) -> Response:
        """Return rate limit exceeded response"""
        return Response(
            content='{"detail": "Rate limit exceeded", "retry_after": 60}',
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Content-Type": "application/json", "Retry-After": "60"}
        )
    
    async def _handle_api_key_caching(self, request: Request):
        """Handle API key validation caching"""
        auth_header = request.headers.get("Authorization", "")
        
        if auth_header.startswith("Bearer ") and auth_header[7:].startswith("pe-"):
            api_key = auth_header[7:]
            
            # Check cache first
            cached_user = await redis_manager.get_cached_api_key_validation(api_key)
            if cached_user:
                request.state.cached_user = cached_user
                request.state.api_key = api_key
                return
            
            # If not cached, the endpoint will handle validation and we'll cache the result
            request.state.api_key = api_key
    
    async def _log_api_usage(self, request: Request, response: Optional[Response], 
                           response_time: float, error: str = None):
        """Log API usage for monitoring"""
        try:
            endpoint = request.url.path
            method = request.method
            status_code = response.status_code if response else 500
            response_time_ms = int(response_time * 1000)
            
            user_id = getattr(request.state, 'user_id', None)
            ip_address = request.client.host
            user_agent = request.headers.get("User-Agent", "")
            
            # Log to database (async, don't wait)
            asyncio.create_task(
                enhanced_database.log_api_usage(
                    endpoint=endpoint,
                    method=method,
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            )
            
        except Exception as e:
            logger.error(f"Error logging API usage: {e}")

class CacheMiddleware:
    """Middleware for caching common responses"""
    
    @staticmethod
    async def cache_api_key_validation(api_key: str, user_data: Dict[str, Any]):
        """Cache API key validation result"""
        if redis_manager.is_available():
            await redis_manager.cache_api_key_validation(api_key, user_data, expire=300)
    
    @staticmethod
    async def get_cached_api_key_validation(api_key: str) -> Optional[Dict[str, Any]]:
        """Get cached API key validation"""
        if redis_manager.is_available():
            return await redis_manager.get_cached_api_key_validation(api_key)
        return None
    
    @staticmethod
    async def invalidate_api_key_cache(api_key: str):
        """Invalidate API key cache when user data changes"""
        if redis_manager.is_available():
            await redis_manager.invalidate_api_key_cache(api_key)
    
    @staticmethod
    async def cache_user_profile(user_id: int, profile_data: Dict[str, Any]):
        """Cache user profile data"""
        if redis_manager.is_available():
            await redis_manager.cache_user_data(user_id, profile_data, expire=600)
    
    @staticmethod
    async def get_cached_user_profile(user_id: int) -> Optional[Dict[str, Any]]:
        """Get cached user profile"""
        if redis_manager.is_available():
            return await redis_manager.get_cached_user_data(user_id)
        return None
    
    @staticmethod
    async def invalidate_user_cache(user_id: int):
        """Invalidate user cache when profile changes"""
        if redis_manager.is_available():
            await redis_manager.invalidate_user_cache(user_id)

# Enhanced API key verification with caching
async def verify_api_key_cached(api_key: str, client_ip: str = None) -> Dict[str, Any]:
    """Verify API key with caching support"""
    
    # Validate format first
    if not SecurityValidator.validate_api_key_format(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format"
        )
    
    # Check cache first
    cached_user = await CacheMiddleware.get_cached_api_key_validation(api_key)
    if cached_user:
        logger.debug(f"API key validation cache hit for key: {api_key[:10]}...")
        return cached_user
    
    # Get from database
    user = await enhanced_database.get_user_by_key(api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Check if user is active
    if not user.get('is_active', False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated"
        )
    
    # Validate IP if whitelisting is enabled
    if client_ip and not validate_ip_address(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not whitelisted"
        )
    
    # Check conversation limits
    limits = json.loads(user.get('limits', '{}'))
    if limits.get('conversation_limit', 0) <= 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Conversation limit exceeded. Limits reset daily."
        )
    
    # Cache the result
    cache_data = {
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'limits': limits,
        'subscription_plan': user.get('subscription_plan', 'free'),
        'level': user.get('level', 'basic')
    }
    
    await CacheMiddleware.cache_api_key_validation(api_key, cache_data)
    
    return cache_data

# Import required functions
import json
from ..security.auth import validate_ip_address

# Connection pooling and async optimization
class AsyncConnectionManager:
    """Manage async connections and optimize concurrent operations"""
    
    def __init__(self, max_concurrent_ops: int = 100):
        self.semaphore = asyncio.Semaphore(max_concurrent_ops)
        self.active_operations = 0
    
    async def execute_with_limit(self, operation):
        """Execute operation with concurrency limit"""
        async with self.semaphore:
            self.active_operations += 1
            try:
                result = await operation
                return result
            finally:
                self.active_operations -= 1
    
    def get_stats(self) -> Dict[str, int]:
        """Get connection manager statistics"""
        return {
            'active_operations': self.active_operations,
            'available_slots': self.semaphore._value
        }

# Global connection manager
connection_manager = AsyncConnectionManager()