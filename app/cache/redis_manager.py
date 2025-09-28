import redis.asyncio as redis
import json
import pickle
from typing import Any, Optional, Union, Dict, List
from datetime import timedelta
import logging
from ..core.config import settings

logger = logging.getLogger(__name__)

class RedisManager:
    """Redis cache and session manager with fallback support"""
    
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis = None
        self._available = False
        
    async def connect(self):
        """Connect to Redis with fallback handling"""
        try:
            self._redis = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=False,  # We'll handle decoding manually
                retry_on_timeout=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            
            # Test connection
            await self._redis.ping()
            self._available = True
            logger.info("Redis connection established")
            
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Falling back to in-memory cache.")
            self._available = False
            self._redis = None
            # Initialize fallback in-memory cache
            self._memory_cache = {}
    
    async def disconnect(self):
        """Close Redis connection"""
        if self._redis:
            await self._redis.close()
            self._redis = None
        self._available = False
    
    def is_available(self) -> bool:
        """Check if Redis is available"""
        return self._available
    
    async def set(self, key: str, value: Any, expire: int = None) -> bool:
        """Set value with optional expiration (seconds)"""
        try:
            if self._available and self._redis:
                # Serialize value
                if isinstance(value, (dict, list)):
                    serialized_value = json.dumps(value).encode('utf-8')
                elif isinstance(value, str):
                    serialized_value = value.encode('utf-8')
                else:
                    serialized_value = pickle.dumps(value)
                
                if expire:
                    await self._redis.setex(key, expire, serialized_value)
                else:
                    await self._redis.set(key, serialized_value)
                return True
            else:
                # Fallback to memory cache
                import time
                self._memory_cache[key] = {
                    'value': value,
                    'expires_at': None if not expire else time.time() + expire
                }
                return True
        except Exception as e:
            logger.error(f"Error setting cache key {key}: {e}")
            return False
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        try:
            if self._available and self._redis:
                value = await self._redis.get(key)
                if value is None:
                    return None
                
                # Try to deserialize as JSON first, then pickle
                try:
                    return json.loads(value.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    try:
                        return value.decode('utf-8')
                    except UnicodeDecodeError:
                        return pickle.loads(value)
            else:
                # Fallback to memory cache
                cache_item = self._memory_cache.get(key)
                if cache_item is None:
                    return None
                
                # Check expiration
                import time
                if cache_item['expires_at'] and cache_item['expires_at'] < time.time():
                    del self._memory_cache[key]
                    return None
                
                return cache_item['value']
        except Exception as e:
            logger.error(f"Error getting cache key {key}: {e}")
            return None
    
    async def delete(self, key: str) -> bool:
        """Delete key"""
        try:
            if self._available and self._redis:
                result = await self._redis.delete(key)
                return result > 0
            else:
                # Fallback to memory cache
                if key in self._memory_cache:
                    del self._memory_cache[key]
                    return True
                return False
        except Exception as e:
            logger.error(f"Error deleting cache key {key}: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            if self._available and self._redis:
                result = await self._redis.exists(key)
                return result > 0
            else:
                # Fallback to memory cache
                cache_item = self._memory_cache.get(key)
                if cache_item is None:
                    return False
                
                # Check expiration
                import time
                if cache_item['expires_at'] and cache_item['expires_at'] < time.time():
                    del self._memory_cache[key]
                    return False
                
                return True
        except Exception as e:
            logger.error(f"Error checking cache key {key}: {e}")
            return False
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter"""
        try:
            if self._available and self._redis:
                return await self._redis.incrby(key, amount)
            else:
                # Fallback to memory cache
                current = self._memory_cache.get(key, {'value': 0})['value']
                new_value = current + amount
                self._memory_cache[key] = {'value': new_value, 'expires_at': None}
                return new_value
        except Exception as e:
            logger.error(f"Error incrementing cache key {key}: {e}")
            return None
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration for key"""
        try:
            if self._available and self._redis:
                return await self._redis.expire(key, seconds)
            else:
                # Fallback to memory cache
                if key in self._memory_cache:
                    import time
                    self._memory_cache[key]['expires_at'] = time.time() + seconds
                    return True
                return False
        except Exception as e:
            logger.error(f"Error setting expiration for cache key {key}: {e}")
            return False
    
    # Session management methods
    async def set_session(self, session_id: str, data: Dict[str, Any], 
                         expire: int = 3600) -> bool:
        """Set session data"""
        return await self.set(f"session:{session_id}", data, expire)
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        return await self.get(f"session:{session_id}")
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        return await self.delete(f"session:{session_id}")
    
    # Rate limiting methods
    async def is_rate_limited(self, key: str, limit: int, window: int) -> bool:
        """Check if rate limit is exceeded"""
        try:
            if self._available and self._redis:
                # Use Redis sliding window
                import time
                current_time = time.time()
                pipeline = self._redis.pipeline()
                
                # Remove old entries
                pipeline.zremrangebyscore(key, 0, current_time - window)
                
                # Count current entries
                pipeline.zcard(key)
                
                # Add current request
                pipeline.zadd(key, {str(current_time): current_time})
                
                # Set expiration
                pipeline.expire(key, window)
                
                results = await pipeline.execute()
                count = results[1]  # zcard result
                
                return count >= limit
            else:
                # Fallback rate limiting using memory
                import time
                rate_key = f"rate:{key}"
                current_time = time.time()
                
                # Get existing data
                rate_data = self._memory_cache.get(rate_key, {'value': [], 'expires_at': None})['value']
                
                # Clean old entries
                rate_data = [t for t in rate_data if t > current_time - window]
                
                # Check limit
                if len(rate_data) >= limit:
                    return True
                
                # Add current request
                rate_data.append(current_time)
                
                # Update cache
                self._memory_cache[rate_key] = {
                    'value': rate_data,
                    'expires_at': current_time + window
                }
                
                return False
        except Exception as e:
            logger.error(f"Error checking rate limit for {key}: {e}")
            # On error, allow the request
            return False
    
    # Caching decorators and utilities
    async def cache_user_data(self, user_id: int, user_data: Dict[str, Any], 
                             expire: int = 300) -> bool:
        """Cache user data for quick access"""
        return await self.set(f"user:{user_id}", user_data, expire)
    
    async def get_cached_user_data(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get cached user data"""
        return await self.get(f"user:{user_id}")
    
    async def invalidate_user_cache(self, user_id: int) -> bool:
        """Invalidate user cache"""
        return await self.delete(f"user:{user_id}")
    
    # API key validation cache
    async def cache_api_key_validation(self, api_key: str, user_data: Dict[str, Any],
                                     expire: int = 300) -> bool:
        """Cache API key validation result"""
        return await self.set(f"api_key:{api_key}", user_data, expire)
    
    async def get_cached_api_key_validation(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Get cached API key validation"""
        return await self.get(f"api_key:{api_key}")
    
    async def invalidate_api_key_cache(self, api_key: str) -> bool:
        """Invalidate API key cache"""
        return await self.delete(f"api_key:{api_key}")
    
    # Health check
    async def health_check(self) -> Dict[str, Any]:
        """Check Redis health"""
        if not self._available:
            return {
                'status': 'unavailable',
                'fallback': 'memory_cache',
                'memory_cache_size': len(getattr(self, '_memory_cache', {}))
            }
        
        try:
            info = await self._redis.info()
            return {
                'status': 'healthy',
                'version': info.get('redis_version', 'unknown'),
                'used_memory': info.get('used_memory_human', 'unknown'),
                'connected_clients': info.get('connected_clients', 0),
                'uptime_seconds': info.get('uptime_in_seconds', 0)
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }


# Global Redis manager instance
redis_manager = RedisManager()