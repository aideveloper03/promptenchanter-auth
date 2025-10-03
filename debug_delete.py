#!/usr/bin/env python3
"""
Debug the delete user functionality
"""

import asyncio
import sys
import os
sys.path.append('/workspace')

import aiosqlite
from app.db.enhanced_database import enhanced_database
import json

async def debug_delete():
    """Debug the delete functionality"""
    
    # Connect to database
    await enhanced_database.connect()
    
    # Check if we can find any users
    print("Checking for users in database...")
    
    async with enhanced_database.get_connection() as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute("SELECT username, is_active FROM users LIMIT 5")
        users = await cursor.fetchall()
        
        print(f"Found {len(users)} users:")
        for user in users:
            user_dict = dict(user)
            print(f"  - {user_dict['username']} (active: {user_dict['is_active']})")
        
        if users:
            # Try to delete the first user
            test_username = dict(users[0])['username']
            print(f"\nTrying to delete user: {test_username}")
            
            # First check if user exists
            user = await enhanced_database.get_user_by_username(test_username)
            if user:
                print(f"User found: {user['username']}")
                
                # Try the delete operation
                result = await enhanced_database.delete_user(test_username, "debug")
                print(f"Delete result: {result}")
                
                # Check if user is now inactive
                user_after = await enhanced_database.get_user_by_username(test_username)
                if user_after:
                    print("User still active after delete")
                else:
                    print("User successfully deactivated")
                    
                # Check deleted_users table
                cursor = await conn.execute("SELECT username FROM deleted_users WHERE username = ?", (test_username,))
                deleted_record = await cursor.fetchone()
                if deleted_record:
                    print("User found in deleted_users table")
                else:
                    print("User NOT found in deleted_users table")
            else:
                print("User not found!")
        else:
            print("No users found in database")
    
    await enhanced_database.disconnect()

if __name__ == "__main__":
    asyncio.run(debug_delete())