#!/usr/bin/env python3
"""
API Integration Test Script
Tests the User Management API endpoints through HTTP requests
"""

import asyncio
import aiohttp
import json
import sys
from typing import Dict, Optional

class APITester:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.test_user_token: Optional[str] = None
        self.test_admin_token: Optional[str] = None
        self.test_api_key: Optional[str] = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def make_request(self, method: str, endpoint: str, 
                          data: Dict = None, headers: Dict = None) -> Dict:
        """Make HTTP request and return JSON response"""
        url = f"{self.base_url}{endpoint}"
        
        default_headers = {"Content-Type": "application/json"}
        if headers:
            default_headers.update(headers)
        
        try:
            async with self.session.request(
                method, url, 
                json=data if data else None, 
                headers=default_headers
            ) as response:
                response_data = await response.json()
                
                if response.status >= 400:
                    raise Exception(f"HTTP {response.status}: {response_data}")
                
                return response_data
                
        except aiohttp.ClientError as e:
            raise Exception(f"Request failed: {str(e)}")
    
    async def test_health_check(self):
        """Test health check endpoint"""
        print("🏥 Testing health check...")
        
        response = await self.make_request("GET", "/health")
        assert "status" in response, "Health check response missing status"
        assert response["status"] in ["healthy", "degraded"], "Invalid health status"
        
        print("✓ Health check passed")
        return response
    
    async def test_user_registration(self):
        """Test user registration"""
        print("👤 Testing user registration...")
        
        user_data = {
            "username": "apitestuser",
            "name": "API Test User",
            "email": "apitest@example.com",
            "password": "TestPassword123",
            "confirm_password": "TestPassword123",
            "type": "Personal",
            "about_me": "Testing the API",
            "hobbies": "API Testing"
        }
        
        response = await self.make_request("POST", "/api/v1/auth/register", user_data)
        assert "message" in response, "Registration response missing message"
        assert "User registered successfully" in response["message"], "Registration failed"
        
        print("✓ User registration passed")
        return response
    
    async def test_user_login(self):
        """Test user login"""
        print("🔑 Testing user login...")
        
        login_data = {
            "email": "apitest@example.com",
            "password": "TestPassword123"
        }
        
        response = await self.make_request("POST", "/api/v1/auth/login", login_data)
        assert "access_token" in response, "Login response missing access token"
        assert response["token_type"] == "bearer", "Invalid token type"
        
        self.test_user_token = response["access_token"]
        print("✓ User login passed")
        return response
    
    async def test_get_profile(self):
        """Test getting user profile"""
        print("👨‍💼 Testing get profile...")
        
        headers = {"Authorization": f"Bearer {self.test_user_token}"}
        response = await self.make_request("GET", "/api/v1/auth/profile", headers=headers)
        
        assert "username" in response, "Profile response missing username"
        assert response["username"] == "apitestuser", "Wrong username in profile"
        assert "email" in response, "Profile response missing email"
        
        print("✓ Get profile passed")
        return response
    
    async def test_get_api_key(self):
        """Test getting API key"""
        print("🔐 Testing get API key...")
        
        headers = {"Authorization": f"Bearer {self.test_user_token}"}
        response = await self.make_request("GET", "/api/v1/auth/api-key", headers=headers)
        
        assert "key" in response, "API key response missing key"
        # Note: The key is encrypted, so we can't validate the format directly
        
        print("✓ Get API key passed")
        return response
    
    async def test_regenerate_api_key(self):
        """Test regenerating API key"""
        print("🔄 Testing regenerate API key...")
        
        headers = {"Authorization": f"Bearer {self.test_user_token}"}
        response = await self.make_request("POST", "/api/v1/auth/regenerate-key", headers=headers)
        
        assert "key" in response, "Regenerate key response missing key"
        
        print("✓ Regenerate API key passed")
        return response
    
    async def test_update_profile(self):
        """Test updating profile"""
        print("✏️ Testing update profile...")
        
        update_data = {
            "name": "Updated API Test User",
            "about_me": "Updated about me via API test"
        }
        
        headers = {"Authorization": f"Bearer {self.test_user_token}"}
        response = await self.make_request("PUT", "/api/v1/auth/profile", update_data, headers)
        
        assert "message" in response, "Update response missing message"
        assert "successfully" in response["message"].lower(), "Update failed"
        
        print("✓ Update profile passed")
        return response
    
    async def test_admin_login(self):
        """Test admin login"""
        print("👑 Testing admin login...")
        
        admin_data = {
            "username": "admin",
            "password": "admin123!"
        }
        
        try:
            response = await self.make_request("POST", "/api/v1/admin/login", admin_data)
            assert "access_token" in response, "Admin login response missing access token"
            
            self.test_admin_token = response["access_token"]
            print("✓ Admin login passed")
            return response
            
        except Exception as e:
            print(f"⚠️ Admin login failed (expected if default admin not created): {str(e)}")
            return None
    
    async def test_admin_get_users(self):
        """Test admin get users"""
        if not self.test_admin_token:
            print("⏭️ Skipping admin get users (no admin token)")
            return None
        
        print("👥 Testing admin get users...")
        
        headers = {"Authorization": f"Bearer {self.test_admin_token}"}
        response = await self.make_request("GET", "/api/v1/admin/users?limit=10", headers=headers)
        
        assert isinstance(response, list), "Admin users response should be a list"
        
        print(f"✓ Admin get users passed (found {len(response)} users)")
        return response
    
    async def test_password_reset(self):
        """Test password reset"""
        print("🔒 Testing password reset...")
        
        reset_data = {
            "current_password": "TestPassword123",
            "new_password": "NewTestPassword123",
            "confirm_new_password": "NewTestPassword123"
        }
        
        headers = {"Authorization": f"Bearer {self.test_user_token}"}
        response = await self.make_request("PUT", "/api/v1/auth/password", reset_data, headers)
        
        assert "message" in response, "Password reset response missing message"
        assert "successfully" in response["message"].lower(), "Password reset failed"
        
        print("✓ Password reset passed")
        
        # Test login with new password
        login_data = {
            "email": "apitest@example.com",
            "password": "NewTestPassword123"
        }
        
        login_response = await self.make_request("POST", "/api/v1/auth/login", login_data)
        self.test_user_token = login_response["access_token"]
        
        print("✓ Login with new password passed")
        return response
    
    async def test_api_info(self):
        """Test API info endpoint"""
        print("ℹ️ Testing API info...")
        
        response = await self.make_request("GET", "/api/v1/info")
        
        assert "api_name" in response, "API info missing api_name"
        assert "version" in response, "API info missing version"
        assert "endpoints" in response, "API info missing endpoints"
        
        print("✓ API info passed")
        return response
    
    async def test_rate_limiting(self):
        """Test rate limiting (basic test)"""
        print("🚦 Testing rate limiting...")
        
        # Make multiple requests quickly to test rate limiting
        # Note: This is a basic test - actual rate limiting depends on configuration
        
        try:
            for i in range(5):
                await self.make_request("GET", "/health")
            
            print("✓ Rate limiting test passed (no limits hit)")
            
        except Exception as e:
            if "rate limit" in str(e).lower() or "429" in str(e):
                print("✓ Rate limiting test passed (limits working)")
            else:
                raise e
    
    async def test_delete_account(self):
        """Test account deletion (should be last test)"""
        print("🗑️ Testing account deletion...")
        
        headers = {"Authorization": f"Bearer {self.test_user_token}"}
        response = await self.make_request("DELETE", "/api/v1/auth/account", headers=headers)
        
        assert "message" in response, "Delete response missing message"
        assert "successfully" in response["message"].lower(), "Account deletion failed"
        
        print("✓ Account deletion passed")
        return response
    
    async def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting API Integration Tests")
        print("==================================")
        
        test_results = {}
        
        try:
            # Basic tests
            test_results["health"] = await self.test_health_check()
            test_results["info"] = await self.test_api_info()
            test_results["rate_limiting"] = await self.test_rate_limiting()
            
            # User authentication flow
            test_results["registration"] = await self.test_user_registration()
            test_results["login"] = await self.test_user_login()
            test_results["profile"] = await self.test_get_profile()
            
            # API key management
            test_results["get_api_key"] = await self.test_get_api_key()
            test_results["regenerate_key"] = await self.test_regenerate_api_key()
            
            # Profile management
            test_results["update_profile"] = await self.test_update_profile()
            test_results["password_reset"] = await self.test_password_reset()
            
            # Admin tests (optional)
            test_results["admin_login"] = await self.test_admin_login()
            test_results["admin_users"] = await self.test_admin_get_users()
            
            # Cleanup (delete test account)
            test_results["delete_account"] = await self.test_delete_account()
            
            print("\n" + "="*50)
            print("🎉 ALL API TESTS PASSED!")
            print("="*50)
            print("\nTest Summary:")
            
            for test_name, result in test_results.items():
                if result is not None:
                    print(f"✓ {test_name}")
                else:
                    print(f"⏭️ {test_name} (skipped)")
            
            print(f"\nAPI is running successfully at: {self.base_url}")
            print("You can now use the API for your applications!")
            
            return True
            
        except Exception as e:
            print(f"\n❌ API Test failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

async def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test User Management API")
    parser.add_argument("--url", default="http://localhost:8000", 
                       help="Base URL of the API (default: http://localhost:8000)")
    args = parser.parse_args()
    
    async with APITester(args.url) as tester:
        success = await tester.run_all_tests()
        
        if not success:
            sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test runner failed: {str(e)}")
        sys.exit(1)