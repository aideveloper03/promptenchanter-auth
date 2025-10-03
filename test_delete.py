#!/usr/bin/env python3
"""
Simple test for account deletion
"""

import asyncio
import aiohttp
import json
import random
import string

async def test_delete():
    """Test account deletion specifically"""
    base_url = "http://localhost:8000"
    
    # Generate random user data
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    test_user = {
        "username": f"deletetest_{random_suffix}",
        "name": "Delete Test User",
        "email": f"deletetest_{random_suffix}@example.com",
        "password": "TestPassword123!",
        "confirm_password": "TestPassword123!",
        "type": "Personal"
    }
    
    async with aiohttp.ClientSession() as session:
        print("🧪 Testing account deletion...")
        
        # Register user
        print("1. Registering user...")
        async with session.post(f"{base_url}/api/v1/auth/register", json=test_user) as response:
            if response.status == 201:
                print("✅ User registered")
            else:
                print(f"❌ Registration failed: {response.status}")
                return False
        
        # Login
        print("2. Logging in...")
        login_data = {"email": test_user["email"], "password": test_user["password"]}
        async with session.post(f"{base_url}/api/v1/auth/login", json=login_data) as response:
            if response.status == 200:
                login_result = await response.json()
                access_token = login_result["access_token"]
                print("✅ Login successful")
            else:
                print(f"❌ Login failed: {response.status}")
                return False
        
        # Delete account
        print("3. Deleting account...")
        headers = {"Authorization": f"Bearer {access_token}"}
        async with session.delete(f"{base_url}/api/v1/auth/account", headers=headers) as response:
            response_text = await response.text()
            print(f"Response status: {response.status}")
            print(f"Response text: {response_text}")
            
            if response.status == 200:
                print("✅ Account deletion successful")
                return True
            else:
                print(f"❌ Account deletion failed: {response.status}")
                try:
                    error_data = json.loads(response_text)
                    print(f"Error details: {error_data}")
                except:
                    print(f"Raw response: {response_text}")
                return False

if __name__ == "__main__":
    try:
        result = asyncio.run(test_delete())
        if result:
            print("\n🎉 Account deletion test passed!")
        else:
            print("\n❌ Account deletion test failed!")
    except Exception as e:
        print(f"\n💥 Test failed: {str(e)}")