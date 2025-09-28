import aiosqlite
import asyncio
import json
import os
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from ..core.config import settings

class Database:
    def __init__(self, db_path: str = "user_management.db"):
        self.db_path = db_path
        self._connection = None
        
    async def connect(self):
        """Establish database connection"""
        self._connection = await aiosqlite.connect(self.db_path)
        await self._connection.execute("PRAGMA foreign_keys = ON")
        await self._connection.commit()
        
    async def disconnect(self):
        """Close database connection"""
        if self._connection:
            await self._connection.close()
            self._connection = None
            
    async def get_connection(self):
        """Get database connection"""
        if not self._connection:
            await self.connect()
        return self._connection
        
    async def init_db(self):
        """Initialize database with all required tables"""
        conn = await self.get_connection()
        
        # Users table
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
        
        # Deleted users table (backup storage)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS deleted_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_user_id INTEGER,
                username TEXT,
                name TEXT,
                email TEXT,
                password_hash TEXT,
                about_me TEXT,
                hobbies TEXT,
                type TEXT,
                time_created TIMESTAMP,
                subscription_plan TEXT,
                credits TEXT,
                limits TEXT,
                access_rtype TEXT,
                level TEXT,
                additional_notes TEXT,
                key TEXT,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                deleted_by TEXT
            )
        """)
        
        # Message logs table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS message_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                model TEXT NOT NULL,
                messages TEXT NOT NULL,
                research_model BOOLEAN DEFAULT 0,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        """)
        
        # Admin table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        """)
        
        # Support staff table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS support_staff (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                staff_level TEXT NOT NULL,
                time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        """)
        
        # Create indexes for better performance
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_key ON users(key)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_message_logs_username ON message_logs(username)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_message_logs_time ON message_logs(time)")
        
        await conn.commit()
        
    async def create_user(self, user_data: Dict[str, Any]) -> Optional[int]:
        """Create a new user"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            INSERT INTO users (username, name, email, password_hash, about_me, hobbies, type, 
                             subscription_plan, credits, limits, access_rtype, level, 
                             additional_notes, key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_data['username'], user_data['name'], user_data['email'],
            user_data['password_hash'], user_data['about_me'], user_data['hobbies'],
            user_data['type'], user_data['subscription_plan'], user_data['credits'],
            user_data['limits'], user_data['access_rtype'], user_data['level'],
            user_data['additional_notes'], user_data['key']
        ))
        await conn.commit()
        return cursor.lastrowid
        
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        conn = await self.get_connection()
        cursor = await conn.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,))
        row = await cursor.fetchone()
        if row:
            columns = [description[0] for description in cursor.description]
            return dict(zip(columns, row))
        return None
        
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        conn = await self.get_connection()
        cursor = await conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        row = await cursor.fetchone()
        if row:
            columns = [description[0] for description in cursor.description]
            return dict(zip(columns, row))
        return None
        
    async def get_user_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        """Get user by API key"""
        conn = await self.get_connection()
        cursor = await conn.execute("SELECT * FROM users WHERE key = ? AND is_active = 1", (key,))
        row = await cursor.fetchone()
        if row:
            columns = [description[0] for description in cursor.description]
            return dict(zip(columns, row))
        return None
        
    async def update_user_limits(self, username: str, new_limits: Dict[str, int]) -> bool:
        """Update user conversation limits"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            UPDATE users SET limits = ? WHERE username = ? AND is_active = 1
        """, (json.dumps(new_limits), username))
        await conn.commit()
        return cursor.rowcount > 0
        
    async def update_user_key(self, username: str, new_key: str) -> bool:
        """Update user API key"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            UPDATE users SET key = ? WHERE username = ? AND is_active = 1
        """, (new_key, username))
        await conn.commit()
        return cursor.rowcount > 0
        
    async def update_user_profile(self, username: str, update_data: Dict[str, Any]) -> bool:
        """Update user profile information"""
        conn = await self.get_connection()
        
        # Build dynamic query
        set_clauses = []
        values = []
        
        for key, value in update_data.items():
            if key in ['name', 'email', 'about_me', 'hobbies', 'type', 'subscription_plan', 
                      'credits', 'limits', 'access_rtype', 'level', 'additional_notes']:
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
        
    async def delete_user(self, username: str, deleted_by: str = "user") -> bool:
        """Soft delete user (move to deleted_users table)"""
        conn = await self.get_connection()
        
        # Get user data first
        user = await self.get_user_by_username(username)
        if not user:
            return False
            
        # Insert into deleted_users table
        await conn.execute("""
            INSERT INTO deleted_users (original_user_id, username, name, email, password_hash,
                                     about_me, hobbies, type, time_created, subscription_plan,
                                     credits, limits, access_rtype, level, additional_notes,
                                     key, deleted_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user['id'], user['username'], user['name'], user['email'], user['password_hash'],
            user['about_me'], user['hobbies'], user['type'], user['time_created'],
            user['subscription_plan'], user['credits'], user['limits'], user['access_rtype'],
            user['level'], user['additional_notes'], user['key'], deleted_by
        ))
        
        # Mark user as inactive
        cursor = await conn.execute("""
            UPDATE users SET is_active = 0 WHERE username = ?
        """, (username,))
        
        await conn.commit()
        return cursor.rowcount > 0
        
    async def log_message(self, log_data: Dict[str, Any]) -> Optional[int]:
        """Log a message"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            INSERT INTO message_logs (username, email, model, messages, research_model)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log_data['username'], log_data['email'], log_data['model'],
            json.dumps(log_data['messages']), log_data['research_model']
        ))
        await conn.commit()
        return cursor.lastrowid
        
    async def batch_log_messages(self, logs: List[Dict[str, Any]]) -> bool:
        """Batch insert message logs"""
        conn = await self.get_connection()
        data = [
            (log['username'], log['email'], log['model'], 
             json.dumps(log['messages']), log['research_model'])
            for log in logs
        ]
        
        await conn.executemany("""
            INSERT INTO message_logs (username, email, model, messages, research_model)
            VALUES (?, ?, ?, ?, ?)
        """, data)
        await conn.commit()
        return True
        
    async def reset_daily_limits(self):
        """Reset conversation limits for all users (called daily)"""
        conn = await self.get_connection()
        
        # Get all users
        cursor = await conn.execute("SELECT username, limits FROM users WHERE is_active = 1")
        users = await cursor.fetchall()
        
        for username, limits_json in users:
            limits = json.loads(limits_json)
            limits['conversation_limit'] = limits.get('reset', 10)
            
            await conn.execute("""
                UPDATE users SET limits = ?, last_limit_reset = CURRENT_TIMESTAMP 
                WHERE username = ?
            """, (json.dumps(limits), username))
            
        await conn.commit()
        
    async def get_all_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get all users with pagination"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            SELECT * FROM users WHERE is_active = 1 
            ORDER BY time_created DESC LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = await cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
        
    async def create_admin(self, username: str, password_hash: str) -> Optional[int]:
        """Create admin user"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            INSERT INTO admins (username, password_hash) VALUES (?, ?)
        """, (username, password_hash))
        await conn.commit()
        return cursor.lastrowid
        
    async def get_admin_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get admin by username"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            SELECT * FROM admins WHERE username = ? AND is_active = 1
        """, (username,))
        row = await cursor.fetchone()
        if row:
            columns = [description[0] for description in cursor.description]
            return dict(zip(columns, row))
        return None
        
    async def create_staff(self, staff_data: Dict[str, Any]) -> Optional[int]:
        """Create support staff"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            INSERT INTO support_staff (name, username, email, password_hash, staff_level)
            VALUES (?, ?, ?, ?, ?)
        """, (
            staff_data['name'], staff_data['username'], staff_data['email'],
            staff_data['password_hash'], staff_data['staff_level']
        ))
        await conn.commit()
        return cursor.lastrowid
        
    async def get_staff_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get staff by username"""
        conn = await self.get_connection()
        cursor = await conn.execute("""
            SELECT * FROM support_staff WHERE username = ? AND is_active = 1
        """, (username,))
        row = await cursor.fetchone()
        if row:
            columns = [description[0] for description in cursor.description]
            return dict(zip(columns, row))
        return None

# Global database instance
database = Database()