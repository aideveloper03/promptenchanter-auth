"""
Background tasks and scheduled jobs
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

try:
    import psutil
except ImportError:
    # Fallback if psutil is not available
    class MockPsutil:
        class VirtualMemory:
            percent = 50.0
            used = 1024 * 1024 * 100
            available = 1024 * 1024 * 500
        
        @staticmethod
        def virtual_memory():
            return MockPsutil.VirtualMemory()
        
        @staticmethod
        def disk_usage(path):
            class DiskUsage:
                total = 1024**4
                used = 1024**3
                free = 1024**4 - 1024**3
            return DiskUsage()
    
    psutil = MockPsutil()

from ..db.database import database
from ..core.config import settings

# Global scheduler instance
scheduler = AsyncIOScheduler()

# In-memory message log buffer for batch processing
message_log_buffer: List[Dict[str, Any]] = []
buffer_lock = asyncio.Lock()

async def reset_daily_limits():
    """Reset conversation limits for all users (runs daily at midnight)"""
    try:
        await database.reset_daily_limits()
        print(f"[{datetime.now()}] Daily limits reset completed")
    except Exception as e:
        print(f"[{datetime.now()}] Error resetting daily limits: {str(e)}")

async def batch_process_message_logs():
    """Process message logs in batches"""
    global message_log_buffer
    
    async with buffer_lock:
        if not message_log_buffer:
            return
        
        try:
            # Process the current buffer
            logs_to_process = message_log_buffer.copy()
            message_log_buffer.clear()
            
            if logs_to_process:
                await database.batch_log_messages(logs_to_process)
                print(f"[{datetime.now()}] Processed {len(logs_to_process)} message logs")
                
        except Exception as e:
            # If batch processing fails, put logs back in buffer
            async with buffer_lock:
                message_log_buffer.extend(logs_to_process)
            print(f"[{datetime.now()}] Error processing message logs: {str(e)}")

async def check_memory_usage():
    """Check memory usage and trigger batch processing if threshold exceeded"""
    memory_usage = psutil.virtual_memory().percent
    memory_mb = psutil.virtual_memory().used / (1024 * 1024)
    
    if memory_mb > settings.MEMORY_THRESHOLD_MB:
        # Only log if there are actually messages to process
        async with buffer_lock:
            if message_log_buffer:
                print(f"[{datetime.now()}] Memory threshold exceeded ({memory_mb:.2f}MB), triggering batch processing")
                await batch_process_message_logs()

async def add_message_to_buffer(message_data: Dict[str, Any]):
    """Add a message to the buffer for batch processing"""
    async with buffer_lock:
        message_log_buffer.append(message_data)
        
        # Check if we should process immediately due to buffer size
        if len(message_log_buffer) >= 100:  # Process if buffer gets too large
            await batch_process_message_logs()

async def cleanup_old_logs():
    """Clean up old message logs (older than 90 days)"""
    try:
        cutoff_date = datetime.now() - timedelta(days=90)
        conn = await database.get_connection()
        
        cursor = await conn.execute("""
            DELETE FROM message_logs WHERE time < ?
        """, (cutoff_date,))
        
        deleted_count = cursor.rowcount
        await conn.commit()
        
        print(f"[{datetime.now()}] Cleaned up {deleted_count} old message logs")
        
    except Exception as e:
        print(f"[{datetime.now()}] Error cleaning up old logs: {str(e)}")

async def generate_usage_statistics():
    """Generate daily usage statistics"""
    try:
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)
        
        conn = await database.get_connection()
        
        # Count messages by model
        cursor = await conn.execute("""
            SELECT model, COUNT(*) as count 
            FROM message_logs 
            WHERE DATE(time) = ? 
            GROUP BY model
        """, (yesterday,))
        
        model_stats = await cursor.fetchall()
        
        # Count active users
        cursor = await conn.execute("""
            SELECT COUNT(DISTINCT username) as active_users 
            FROM message_logs 
            WHERE DATE(time) = ?
        """, (yesterday,))
        
        active_users = await cursor.fetchone()
        
        print(f"[{datetime.now()}] Usage stats for {yesterday}:")
        print(f"  Active users: {active_users[0] if active_users else 0}")
        for model, count in model_stats:
            print(f"  {model}: {count} messages")
            
    except Exception as e:
        print(f"[{datetime.now()}] Error generating usage statistics: {str(e)}")

def start_scheduler():
    """Start the background scheduler"""
    # Reset daily limits at midnight
    scheduler.add_job(
        reset_daily_limits,
        CronTrigger(hour=0, minute=0),
        id="reset_daily_limits",
        replace_existing=True
    )
    
    # Batch process message logs every N minutes
    scheduler.add_job(
        batch_process_message_logs,
        IntervalTrigger(minutes=settings.BATCH_LOG_INTERVAL_MINUTES),
        id="batch_process_logs",
        replace_existing=True
    )
    
    # Check memory usage every 10 minutes
    scheduler.add_job(
        check_memory_usage,
        IntervalTrigger(minutes=10),
        id="check_memory",
        replace_existing=True
    )
    
    # Clean up old logs weekly (Sunday at 2 AM)
    scheduler.add_job(
        cleanup_old_logs,
        CronTrigger(day_of_week=6, hour=2, minute=0),
        id="cleanup_old_logs",
        replace_existing=True
    )
    
    # Generate usage statistics daily at 1 AM
    scheduler.add_job(
        generate_usage_statistics,
        CronTrigger(hour=1, minute=0),
        id="usage_statistics",
        replace_existing=True
    )
    
    scheduler.start()
    print(f"[{datetime.now()}] Background scheduler started")

def stop_scheduler():
    """Stop the background scheduler"""
    scheduler.shutdown()
    print(f"[{datetime.now()}] Background scheduler stopped")

# Rate limiting utilities
class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests = {}
        self.cleanup_interval = 300  # Clean up every 5 minutes
        self.last_cleanup = datetime.now()
    
    async def is_allowed(self, identifier: str, limit: int = None, window: int = 60) -> bool:
        """
        Check if request is allowed based on rate limit
        
        Args:
            identifier: Unique identifier (IP, user, etc.)
            limit: Number of requests allowed in window
            window: Time window in seconds
            
        Returns:
            bool: True if request is allowed
        """
        if limit is None:
            limit = settings.RATE_LIMIT_PER_MINUTE
        
        now = datetime.now()
        
        # Clean up old entries periodically
        if (now - self.last_cleanup).seconds > self.cleanup_interval:
            await self._cleanup_old_entries()
            self.last_cleanup = now
        
        # Initialize if not exists
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove old requests outside the window
        cutoff_time = now - timedelta(seconds=window)
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier] 
            if req_time > cutoff_time
        ]
        
        # Check if limit exceeded
        if len(self.requests[identifier]) >= limit:
            return False
        
        # Add current request
        self.requests[identifier].append(now)
        return True
    
    async def _cleanup_old_entries(self):
        """Clean up old rate limit entries"""
        cutoff_time = datetime.now() - timedelta(minutes=5)
        
        for identifier in list(self.requests.keys()):
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > cutoff_time
            ]
            
            # Remove empty entries
            if not self.requests[identifier]:
                del self.requests[identifier]

# Global rate limiter instance
rate_limiter = RateLimiter()

# Health check utilities
async def health_check() -> Dict[str, Any]:
    """Perform system health check"""
    try:
        # Check database connection
        await database.get_connection()
        db_status = "healthy"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    # Check memory usage
    memory = psutil.virtual_memory()
    
    # Check disk usage
    disk = psutil.disk_usage('/')
    
    # Check message buffer size
    buffer_size = len(message_log_buffer)
    
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "timestamp": datetime.now().isoformat(),
        "database": db_status,
        "memory": {
            "used_percent": memory.percent,
            "used_mb": memory.used / (1024 * 1024),
            "available_mb": memory.available / (1024 * 1024)
        },
        "disk": {
            "used_percent": (disk.used / disk.total) * 100,
            "free_gb": disk.free / (1024**3)
        },
        "message_buffer_size": buffer_size,
        "scheduler_running": scheduler.running
    }