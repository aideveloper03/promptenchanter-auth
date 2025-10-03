import aiosqlite
import asyncio
import json
import os
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from ..core.config import settings
import logging

logger = logging.getLogger(__name__)

class ConnectionPool:
    """Simple connection pool for SQLite"""
    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self._pool = asyncio.Queue(maxsize=max_connections)
        self._created_connections = 0
        self._lock = asyncio.Lock()
        
    async def get_connection(self):
        """Get a connection from the pool"""
        try:
            # Try to get existing connection
            connection = self._pool.get_nowait()
            return connection
        except asyncio.QueueEmpty:
            # Create new connection if under limit
            async with self._lock:
                if self._created_connections < self.max_connections:
                    connection = await aiosqlite.connect(self.db_path)
                    await connection.execute("PRAGMA foreign_keys = ON")
                    await connection.execute("PRAGMA journal_mode = WAL")
                    await connection.execute("PRAGMA synchronous = NORMAL")
                    await connection.execute("PRAGMA cache_size = 1000")
                    await connection.execute("PRAGMA temp_store = MEMORY")
                    self._created_connections += 1
                    return connection
                else:
                    # Wait for an available connection
                    return await self._pool.get()
    
    async def return_connection(self, connection):
        """Return a connection to the pool"""
        try:
            self._pool.put_nowait(connection)
        except asyncio.QueueFull:
            # Pool is full, close the connection
            await connection.close()
            async with self._lock:
                self._created_connections -= 1
    
    async def close_all(self):
        """Close all connections in the pool"""
        connections = []
        while not self._pool.empty():
            try:
                connections.append(self._pool.get_nowait())
            except asyncio.QueueEmpty:
                break
        
        for conn in connections:
            await conn.close()
        
        self._created_connections = 0

class EnhancedDatabase:
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Extract path from DATABASE_URL
            db_url = settings.DATABASE_URL
            if db_url.startswith("sqlite:///"):
                db_path = db_url[10:]  # Remove sqlite:/// prefix
            else:
                db_path = "./user_management.db"
        
        self.db_path = db_path
        self._pool = None
        self._initialized = False
        
    async def connect(self):
        """Initialize connection pool"""
        if not self._pool:
            self._pool = ConnectionPool(self.db_path, max_connections=10)
        
        if not self._initialized:
            await self.init_db()
            self._initialized = True
    
    async def disconnect(self):
        """Close all connections"""
        if self._pool:
            await self._pool.close_all()
            self._pool = None
    
    @asynccontextmanager
    async def get_connection(self):
        """Context manager for database connections"""
        if not self._pool:
            await self.connect()
        
        connection = await self._pool.get_connection()
        try:
            yield connection
        finally:
            await self._pool.return_connection(connection)
    
    async def init_db(self):
        """Initialize database with optimized schema"""
        async with self.get_connection() as conn:
            # Users table with indexes
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    about_me TEXT DEFAULT '',
                    hobbies TEXT DEFAULT '',
                    type TEXT NOT NULL DEFAULT 'Personal',
                    time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    subscription_plan TEXT DEFAULT 'free',
                    credits TEXT DEFAULT '{"main":5, "reset":5}',
                    limits TEXT DEFAULT '{"conversation_limit":10, "reset":10}',
                    access_rtype TEXT DEFAULT '["bpe","tot"]',
                    level TEXT DEFAULT 'basic',
                    additional_notes TEXT DEFAULT '',
                    key TEXT UNIQUE NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    last_limit_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_key ON users(key)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_created ON users(time_created)")
            
            # Admins table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username)")
            
            # Staff table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS support_staff (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    staff_level TEXT NOT NULL DEFAULT 'support',
                    time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_staff_username ON support_staff(username)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_staff_email ON support_staff(email)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_staff_active ON support_staff(is_active)")
            
            # Message logs table with partitioning-like approach
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS message_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    model TEXT NOT NULL,
                    messages TEXT NOT NULL,
                    research_model BOOLEAN DEFAULT 0,
                    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_message_logs_username ON message_logs(username)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_message_logs_time ON message_logs(time)")
            
            # Deleted users table for backup
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS deleted_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_user_id INTEGER,
                    username TEXT NOT NULL,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    deletion_reason TEXT,
                    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    deleted_by TEXT,
                    user_data TEXT
                )
            """)
            
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deleted_users_username ON deleted_users(username)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deleted_users_deleted_at ON deleted_users(deleted_at)")
            
            # API usage stats table for monitoring
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS api_usage_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE NOT NULL,
                    endpoint TEXT NOT NULL,
                    method TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_time_ms INTEGER,
                    user_id INTEGER,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_stats_date ON api_usage_stats(date)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_stats_endpoint ON api_usage_stats(endpoint)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_stats_user ON api_usage_stats(user_id)")
            
            await conn.commit()
    
    # Optimized user operations with caching potential
    async def create_user(self, user_data: Dict[str, Any]) -> Optional[int]:
        """Create a new user with optimized insert"""
        async with self.get_connection() as conn:
            try:
                cursor = await conn.execute("""
                    INSERT INTO users (
                        username, name, email, password_hash, about_me, hobbies, type,
                        subscription_plan, credits, limits, access_rtype, level,
                        additional_notes, key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_data['username'], user_data['name'], user_data['email'],
                    user_data['password_hash'], user_data.get('about_me', ''),
                    user_data.get('hobbies', ''), user_data['type'],
                    user_data.get('subscription_plan', 'free'),
                    user_data.get('credits', '{"main":5, "reset":5}'),
                    user_data.get('limits', '{"conversation_limit":10, "reset":10}'),
                    user_data.get('access_rtype', '["bpe","tot"]'),
                    user_data.get('level', 'basic'),
                    user_data.get('additional_notes', ''),
                    user_data['key']
                ))
                await conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return None
    
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email with optimized query"""
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT * FROM users WHERE email = ? AND is_active = 1
            """, (email,))
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username with optimized query"""
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT * FROM users WHERE username = ? AND is_active = 1
            """, (username,))
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def get_user_by_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Get user by API key with optimized query"""
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT * FROM users WHERE key = ? AND is_active = 1
            """, (api_key,))
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def update_user_limits(self, username: str, limits: Dict[str, int]) -> bool:
        """Update user limits with atomic operation"""
        async with self.get_connection() as conn:
            try:
                cursor = await conn.execute("""
                    UPDATE users SET limits = ? WHERE username = ? AND is_active = 1
                """, (json.dumps(limits), username))
                await conn.commit()
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Error updating user limits: {e}")
                return False
    
    async def update_user_key(self, username: str, new_key: str) -> bool:
        """Update user API key"""
        async with self.get_connection() as conn:
            try:
                cursor = await conn.execute("""
                    UPDATE users SET key = ? WHERE username = ? AND is_active = 1
                """, (new_key, username))
                await conn.commit()
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Error updating user key: {e}")
                return False
    
    async def update_user_profile(self, username: str, update_data: Dict[str, Any]) -> bool:
        """Update user profile information"""
        async with self.get_connection() as conn:
            try:
                # Build dynamic query
                set_clauses = []
                values = []
                
                allowed_fields = ['name', 'email', 'about_me', 'hobbies', 'type', 'subscription_plan', 
                                'credits', 'limits', 'access_rtype', 'level', 'additional_notes', 'password_hash']
                
                for key, value in update_data.items():
                    if key in allowed_fields:
                        set_clauses.append(f"{key} = ?")
                        if isinstance(value, (dict, list)):
                            values.append(json.dumps(value))
                        else:
                            values.append(value)
                
                if not set_clauses:
                    return False
                    
                values.append(username)
                query = f"UPDATE users SET {', '.join(set_clauses)} WHERE username = ? AND is_active = 1"
                
                cursor = await conn.execute(query, values)
                await conn.commit()
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Error updating user profile: {e}")
                return False
    
    async def batch_log_messages(self, messages: List[Dict[str, Any]]) -> bool:
        """Batch insert messages for better performance"""
        if not messages:
            return True
        
        async with self.get_connection() as conn:
            try:
                await conn.executemany("""
                    INSERT INTO message_logs (username, email, model, messages, research_model)
                    VALUES (?, ?, ?, ?, ?)
                """, [
                    (msg['username'], msg['email'], msg['model'], 
                     json.dumps(msg['messages']), msg.get('research_model', False))
                    for msg in messages
                ])
                await conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error batch logging messages: {e}")
                return False
    
    async def get_users_paginated(self, limit: int = 50, offset: int = 0, 
                                 search: str = None) -> List[Dict[str, Any]]:
        """Get users with pagination and search"""
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            if search:
                cursor = await conn.execute("""
                    SELECT * FROM users 
                    WHERE is_active = 1 AND (
                        username LIKE ? OR 
                        name LIKE ? OR 
                        email LIKE ?
                    )
                    ORDER BY time_created DESC
                    LIMIT ? OFFSET ?
                """, (f"%{search}%", f"%{search}%", f"%{search}%", limit, offset))
            else:
                cursor = await conn.execute("""
                    SELECT * FROM users 
                    WHERE is_active = 1
                    ORDER BY time_created DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
            
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def reset_daily_limits(self) -> bool:
        """Reset all user conversation limits (daily task)"""
        async with self.get_connection() as conn:
            try:
                conn.row_factory = aiosqlite.Row
                # Get all users with their reset limits
                cursor = await conn.execute("""
                    SELECT id, username, limits FROM users WHERE is_active = 1
                """)
                users = await cursor.fetchall()
                
                # Prepare batch update
                updates = []
                for user in users:
                    user_dict = dict(user)
                    limits = json.loads(user_dict['limits'])
                    if 'reset' in limits:
                        limits['conversation_limit'] = limits['reset']
                        updates.append((json.dumps(limits), user_dict['id']))
                
                # Batch update
                await conn.executemany("""
                    UPDATE users SET limits = ?, last_limit_reset = CURRENT_TIMESTAMP 
                    WHERE id = ?
                """, updates)
                
                await conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error resetting daily limits: {e}")
                return False
    
    async def log_api_usage(self, endpoint: str, method: str, status_code: int,
                           response_time_ms: int, user_id: int = None,
                           ip_address: str = None, user_agent: str = None) -> bool:
        """Log API usage for monitoring"""
        async with self.get_connection() as conn:
            try:
                await conn.execute("""
                    INSERT INTO api_usage_stats 
                    (date, endpoint, method, status_code, response_time_ms, 
                     user_id, ip_address, user_agent)
                    VALUES (DATE('now'), ?, ?, ?, ?, ?, ?, ?)
                """, (endpoint, method, status_code, response_time_ms,
                      user_id, ip_address, user_agent))
                await conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error logging API usage: {e}")
                return False
    
    async def get_usage_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get usage statistics for the last N days"""
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT 
                    date,
                    COUNT(*) as total_requests,
                    AVG(response_time_ms) as avg_response_time,
                    COUNT(DISTINCT user_id) as unique_users,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
                FROM api_usage_stats 
                WHERE date >= DATE('now', '-{} days')
                GROUP BY date
                ORDER BY date DESC
            """.format(days))
            
            stats = await cursor.fetchall()
            return {
                'daily_stats': [dict(row) for row in stats],
                'period_days': days
            }
    
    # Cleanup operations
    async def cleanup_old_logs(self, days_to_keep: int = 90) -> bool:
        """Remove old message logs to maintain performance"""
        async with self.get_connection() as conn:
            try:
                await conn.execute("""
                    DELETE FROM message_logs 
                    WHERE time < DATETIME('now', '-{} days')
                """.format(days_to_keep))
                
                await conn.execute("""
                    DELETE FROM api_usage_stats 
                    WHERE date < DATE('now', '-{} days')
                """.format(days_to_keep))
                
                await conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error cleaning up old logs: {e}")
                return False
    
    # Add methods from original database class that are missing
    async def create_admin(self, username: str, password_hash: str) -> Optional[int]:
        """Create admin user"""
        async with self.get_connection() as conn:
            try:
                cursor = await conn.execute("""
                    INSERT INTO admins (username, password_hash)
                    VALUES (?, ?)
                """, (username, password_hash))
                await conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Error creating admin: {e}")
                return None
    
    async def get_admin_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get admin by username"""
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT * FROM admins WHERE username = ?
            """, (username,))
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def create_staff(self, staff_data: Dict[str, Any]) -> Optional[int]:
        """Create staff member"""
        async with self.get_connection() as conn:
            try:
                cursor = await conn.execute("""
                    INSERT INTO support_staff (name, username, email, password_hash, staff_level)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    staff_data['name'], staff_data['username'], 
                    staff_data['email'], staff_data['password_hash'],
                    staff_data.get('staff_level', 'support')
                ))
                await conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Error creating staff: {e}")
                return None
    
    async def get_staff_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get staff by username"""
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT * FROM support_staff WHERE username = ? AND is_active = 1
            """, (username,))
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def log_message(self, message_data: Dict[str, Any]) -> Optional[int]:
        """Log single message"""
        async with self.get_connection() as conn:
            try:
                cursor = await conn.execute("""
                    INSERT INTO message_logs (username, email, model, messages, research_model)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    message_data['username'], message_data['email'], 
                    message_data['model'], json.dumps(message_data['messages']),
                    message_data.get('research_model', False)
                ))
                await conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Error logging message: {e}")
                return None
    
    async def delete_user(self, username: str, deleted_by: str) -> bool:
        """Soft delete user with backup"""
        async with self.get_connection() as conn:
            try:
                conn.row_factory = aiosqlite.Row
                # Get user data first
                cursor = await conn.execute("""
                    SELECT * FROM users WHERE username = ? AND is_active = 1
                """, (username,))
                user = await cursor.fetchone()
                
                if not user:
                    logger.error(f"User {username} not found for deletion")
                    return False
                
                user_dict = dict(user)
                
                # Backup user data
                await conn.execute("""
                    INSERT INTO deleted_users 
                    (original_user_id, username, name, email, deletion_reason, 
                     deleted_by, user_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_dict['id'], user_dict['username'], user_dict['name'],
                    user_dict['email'], 'User requested deletion', deleted_by,
                    json.dumps(user_dict)
                ))
                
                # Soft delete
                cursor = await conn.execute("""
                    UPDATE users SET is_active = 0 WHERE username = ?
                """, (username,))
                
                await conn.commit()
                
                # Check if the update was successful
                if cursor.rowcount > 0:
                    logger.info(f"Successfully deleted user {username}")
                    return True
                else:
                    logger.error(f"Failed to update user {username} - no rows affected")
                    return False
                    
            except Exception as e:
                logger.error(f"Error deleting user {username}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                return False

# Create database instance
enhanced_database = EnhancedDatabase()