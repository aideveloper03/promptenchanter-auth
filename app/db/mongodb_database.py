"""
MongoDB Database Manager
Handles all database operations using MongoDB with _1 suffix collections
"""

import asyncio
import json
import os
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
from pymongo import IndexModel, ASCENDING, DESCENDING
from bson import ObjectId
from ..core.config import settings

class MongoDatabase:
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None
        self._connection_string = None
        
    async def connect(self):
        """Establish MongoDB connection"""
        try:
            # Use MongoDB connection string from environment or default
            self._connection_string = getattr(settings, 'MONGODB_URI', 
                "mongodb+srv://aideveloper03690_db_user:c0evekYI3q2EnpuY@cluster0.cptyxpt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
            
            # Create client with server API
            self.client = AsyncIOMotorClient(
                self._connection_string,
                server_api=ServerApi('1')
            )
            
            # Get database
            self.db = self.client.user_management
            
            # Test connection
            await self.client.admin.command('ping')
            print("Successfully connected to MongoDB!")
            
            # Initialize collections and indexes
            await self._init_collections()
            
        except Exception as e:
            print(f"Failed to connect to MongoDB: {str(e)}")
            raise
            
    async def disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.client = None
            self.db = None
            
    async def _init_collections(self):
        """Initialize collections with indexes"""
        try:
            # Create collections with _1 suffix
            collections = {
                'users_1': [
                    IndexModel([("username", ASCENDING)], unique=True),
                    IndexModel([("email", ASCENDING)], unique=True),
                    IndexModel([("key", ASCENDING)], unique=True),
                    IndexModel([("is_active", ASCENDING)]),
                ],
                'deleted_users_1': [
                    IndexModel([("original_user_id", ASCENDING)]),
                    IndexModel([("username", ASCENDING)]),
                    IndexModel([("deleted_at", DESCENDING)]),
                ],
                'message_logs_1': [
                    IndexModel([("username", ASCENDING)]),
                    IndexModel([("time", DESCENDING)]),
                    IndexModel([("email", ASCENDING)]),
                ],
                'admins_1': [
                    IndexModel([("username", ASCENDING)], unique=True),
                    IndexModel([("is_active", ASCENDING)]),
                ],
                'support_staff_1': [
                    IndexModel([("username", ASCENDING)], unique=True),
                    IndexModel([("email", ASCENDING)], unique=True),
                    IndexModel([("is_active", ASCENDING)]),
                ],
                'email_verifications_1': [
                    IndexModel([("email", ASCENDING)]),
                    IndexModel([("otp", ASCENDING)]),
                    IndexModel([("expires_at", ASCENDING)]),
                    IndexModel([("created_at", DESCENDING)]),
                ]
            }
            
            for collection_name, indexes in collections.items():
                collection = self.db[collection_name]
                
                # Create indexes
                if indexes:
                    await collection.create_indexes(indexes)
                    
            print("MongoDB collections and indexes initialized successfully!")
            
        except Exception as e:
            print(f"Error initializing MongoDB collections: {str(e)}")
            raise
            
    async def get_connection(self):
        """Get database connection (for compatibility)"""
        if not self.client:
            await self.connect()
        return self
        
    # User operations
    async def create_user(self, user_data: Dict[str, Any]) -> Optional[str]:
        """Create a new user"""
        try:
            # Convert data for MongoDB
            mongo_data = {
                'username': user_data['username'],
                'name': user_data['name'],
                'email': user_data['email'],
                'password_hash': user_data['password_hash'],
                'about_me': user_data['about_me'],
                'hobbies': user_data['hobbies'],
                'type': user_data['type'],
                'time_created': datetime.utcnow(),
                'subscription_plan': user_data['subscription_plan'],
                'credits': json.loads(user_data['credits']) if isinstance(user_data['credits'], str) else user_data['credits'],
                'limits': json.loads(user_data['limits']) if isinstance(user_data['limits'], str) else user_data['limits'],
                'access_rtype': json.loads(user_data['access_rtype']) if isinstance(user_data['access_rtype'], str) else user_data['access_rtype'],
                'level': user_data['level'],
                'additional_notes': user_data['additional_notes'],
                'key': user_data['key'],
                'is_active': True,
                'last_limit_reset': datetime.utcnow(),
                'email_verified': False,  # New field for email verification
                'verification_attempts': 0  # Track verification attempts
            }
            
            result = await self.db.users_1.insert_one(mongo_data)
            return str(result.inserted_id)
            
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            return None
            
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            user = await self.db.users_1.find_one({"email": email, "is_active": True})
            if user:
                user['id'] = str(user['_id'])
                return user
            return None
        except Exception as e:
            print(f"Error getting user by email: {str(e)}")
            return None
            
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        try:
            user = await self.db.users_1.find_one({"username": username, "is_active": True})
            if user:
                user['id'] = str(user['_id'])
                return user
            return None
        except Exception as e:
            print(f"Error getting user by username: {str(e)}")
            return None
            
    async def get_user_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        """Get user by API key"""
        try:
            user = await self.db.users_1.find_one({"key": key, "is_active": True})
            if user:
                user['id'] = str(user['_id'])
                return user
            return None
        except Exception as e:
            print(f"Error getting user by key: {str(e)}")
            return None
            
    async def update_user_limits(self, username: str, new_limits: Dict[str, int]) -> bool:
        """Update user conversation limits"""
        try:
            result = await self.db.users_1.update_one(
                {"username": username, "is_active": True},
                {"$set": {"limits": new_limits}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating user limits: {str(e)}")
            return False
            
    async def update_user_key(self, username: str, new_key: str) -> bool:
        """Update user API key"""
        try:
            result = await self.db.users_1.update_one(
                {"username": username, "is_active": True},
                {"$set": {"key": new_key}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating user key: {str(e)}")
            return False
            
    async def update_user_profile(self, username: str, update_data: Dict[str, Any]) -> bool:
        """Update user profile information"""
        try:
            # Convert JSON strings to objects if needed
            processed_data = {}
            for key, value in update_data.items():
                if key in ['credits', 'limits', 'access_rtype'] and isinstance(value, str):
                    processed_data[key] = json.loads(value)
                else:
                    processed_data[key] = value
                    
            result = await self.db.users_1.update_one(
                {"username": username, "is_active": True},
                {"$set": processed_data}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating user profile: {str(e)}")
            return False
            
    async def delete_user(self, username: str, deleted_by: str = "user") -> bool:
        """Soft delete user (move to deleted_users_1 collection)"""
        try:
            # Get user data first
            user = await self.get_user_by_username(username)
            if not user:
                return False
                
            # Insert into deleted_users_1 collection
            deleted_user_data = {
                'original_user_id': user['id'],
                'username': user['username'],
                'name': user['name'],
                'email': user['email'],
                'password_hash': user['password_hash'],
                'about_me': user['about_me'],
                'hobbies': user['hobbies'],
                'type': user['type'],
                'time_created': user['time_created'],
                'subscription_plan': user['subscription_plan'],
                'credits': user['credits'],
                'limits': user['limits'],
                'access_rtype': user['access_rtype'],
                'level': user['level'],
                'additional_notes': user['additional_notes'],
                'key': user['key'],
                'deleted_at': datetime.utcnow(),
                'deleted_by': deleted_by
            }
            
            await self.db.deleted_users_1.insert_one(deleted_user_data)
            
            # Mark user as inactive
            result = await self.db.users_1.update_one(
                {"username": username},
                {"$set": {"is_active": False}}
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            print(f"Error deleting user: {str(e)}")
            return False
            
    # Message logging operations
    async def log_message(self, log_data: Dict[str, Any]) -> Optional[str]:
        """Log a message"""
        try:
            mongo_data = {
                'username': log_data['username'],
                'email': log_data['email'],
                'model': log_data['model'],
                'messages': log_data['messages'],
                'research_model': log_data['research_model'],
                'time': datetime.utcnow()
            }
            
            result = await self.db.message_logs_1.insert_one(mongo_data)
            return str(result.inserted_id)
            
        except Exception as e:
            print(f"Error logging message: {str(e)}")
            return None
            
    async def batch_log_messages(self, logs: List[Dict[str, Any]]) -> bool:
        """Batch insert message logs"""
        try:
            mongo_logs = []
            for log in logs:
                mongo_data = {
                    'username': log['username'],
                    'email': log['email'],
                    'model': log['model'],
                    'messages': log['messages'],
                    'research_model': log['research_model'],
                    'time': datetime.utcnow()
                }
                mongo_logs.append(mongo_data)
                
            await self.db.message_logs_1.insert_many(mongo_logs)
            return True
            
        except Exception as e:
            print(f"Error batch logging messages: {str(e)}")
            return False
            
    async def reset_daily_limits(self):
        """Reset conversation limits for all users (called daily)"""
        try:
            # Get all users
            users = self.db.users_1.find({"is_active": True})
            
            async for user in users:
                limits = user.get('limits', {})
                limits['conversation_limit'] = limits.get('reset', 10)
                
                await self.db.users_1.update_one(
                    {"_id": user['_id']},
                    {
                        "$set": {
                            "limits": limits,
                            "last_limit_reset": datetime.utcnow()
                        }
                    }
                )
                
        except Exception as e:
            print(f"Error resetting daily limits: {str(e)}")
            
    async def get_all_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get all users with pagination"""
        try:
            cursor = self.db.users_1.find({"is_active": True}).sort("time_created", -1).skip(offset).limit(limit)
            users = []
            
            async for user in cursor:
                user['id'] = str(user['_id'])
                users.append(user)
                
            return users
            
        except Exception as e:
            print(f"Error getting all users: {str(e)}")
            return []
            
    # Admin operations
    async def create_admin(self, username: str, password_hash: str) -> Optional[str]:
        """Create admin user"""
        try:
            admin_data = {
                'username': username,
                'password_hash': password_hash,
                'created_at': datetime.utcnow(),
                'is_active': True
            }
            
            result = await self.db.admins_1.insert_one(admin_data)
            return str(result.inserted_id)
            
        except Exception as e:
            print(f"Error creating admin: {str(e)}")
            return None
            
    async def get_admin_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get admin by username"""
        try:
            admin = await self.db.admins_1.find_one({"username": username, "is_active": True})
            if admin:
                admin['id'] = str(admin['_id'])
                return admin
            return None
        except Exception as e:
            print(f"Error getting admin by username: {str(e)}")
            return None
            
    # Staff operations
    async def create_staff(self, staff_data: Dict[str, Any]) -> Optional[str]:
        """Create support staff"""
        try:
            mongo_data = {
                'name': staff_data['name'],
                'username': staff_data['username'],
                'email': staff_data['email'],
                'password_hash': staff_data['password_hash'],
                'staff_level': staff_data['staff_level'],
                'time_created': datetime.utcnow(),
                'is_active': True
            }
            
            result = await self.db.support_staff_1.insert_one(mongo_data)
            return str(result.inserted_id)
            
        except Exception as e:
            print(f"Error creating staff: {str(e)}")
            return None
            
    async def get_staff_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get staff by username"""
        try:
            staff = await self.db.support_staff_1.find_one({"username": username, "is_active": True})
            if staff:
                staff['id'] = str(staff['_id'])
                return staff
            return None
        except Exception as e:
            print(f"Error getting staff by username: {str(e)}")
            return None
            
    # Email verification operations
    async def create_email_verification(self, email: str, otp: str, expires_at: datetime) -> Optional[str]:
        """Create email verification record"""
        try:
            verification_data = {
                'email': email,
                'otp': otp,
                'expires_at': expires_at,
                'created_at': datetime.utcnow(),
                'is_used': False
            }
            
            result = await self.db.email_verifications_1.insert_one(verification_data)
            return str(result.inserted_id)
            
        except Exception as e:
            print(f"Error creating email verification: {str(e)}")
            return None
            
    async def get_email_verification(self, email: str, otp: str) -> Optional[Dict[str, Any]]:
        """Get email verification record"""
        try:
            verification = await self.db.email_verifications_1.find_one({
                "email": email,
                "otp": otp,
                "is_used": False,
                "expires_at": {"$gt": datetime.utcnow()}
            })
            
            if verification:
                verification['id'] = str(verification['_id'])
                return verification
            return None
            
        except Exception as e:
            print(f"Error getting email verification: {str(e)}")
            return None
            
    async def mark_verification_used(self, verification_id: str) -> bool:
        """Mark verification as used"""
        try:
            result = await self.db.email_verifications_1.update_one(
                {"_id": ObjectId(verification_id)},
                {"$set": {"is_used": True}}
            )
            return result.modified_count > 0
            
        except Exception as e:
            print(f"Error marking verification as used: {str(e)}")
            return False
            
    async def update_email_verification_status(self, username: str, verified: bool = True) -> bool:
        """Update user email verification status"""
        try:
            result = await self.db.users_1.update_one(
                {"username": username, "is_active": True},
                {"$set": {"email_verified": verified}}
            )
            return result.modified_count > 0
            
        except Exception as e:
            print(f"Error updating email verification status: {str(e)}")
            return False
            
    async def get_verification_attempts_today(self, email: str) -> int:
        """Get number of verification attempts today"""
        try:
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            
            count = await self.db.email_verifications_1.count_documents({
                "email": email,
                "created_at": {"$gte": today_start}
            })
            
            return count
            
        except Exception as e:
            print(f"Error getting verification attempts: {str(e)}")
            return 0
            
    # Usage statistics
    async def get_usage_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get usage statistics"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get user count
            total_users = await self.db.users_1.count_documents({"is_active": True})
            
            # Get new users in period
            new_users = await self.db.users_1.count_documents({
                "is_active": True,
                "time_created": {"$gte": start_date}
            })
            
            # Get message count in period
            message_count = await self.db.message_logs_1.count_documents({
                "time": {"$gte": start_date}
            })
            
            return {
                "total_users": total_users,
                "new_users_last_7_days": new_users,
                "messages_last_7_days": message_count,
                "period_days": days
            }
            
        except Exception as e:
            print(f"Error getting usage stats: {str(e)}")
            return {}

# Global database instance
mongodb_database = MongoDatabase()