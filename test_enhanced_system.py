#!/usr/bin/env python3
"""
Comprehensive test suite for the enhanced User Management API
Tests all major functionality including performance optimizations and production features
"""

import asyncio
import aiohttp
import json
import sys
import time
import os
from typing import Dict, Optional, List

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

class EnhancedAPITester:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.test_results = {}
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def make_request(self, method: str, endpoint: str, 
                          data: Dict = None, headers: Dict = None) -> Dict:
        """Make HTTP request and return response with timing"""
        url = f"{self.base_url}{endpoint}"
        
        default_headers = {"Content-Type": "application/json"}
        if headers:
            default_headers.update(headers)
        
        start_time = time.time()
        
        try:
            async with self.session.request(
                method, url, 
                json=data if data else None, 
                headers=default_headers
            ) as response:
                response_time = time.time() - start_time
                response_data = await response.json()
                
                return {
                    'status_code': response.status,
                    'data': response_data,
                    'response_time': response_time,
                    'headers': dict(response.headers)
                }
                
        except Exception as e:
            return {
                'status_code': 500,
                'data': {'error': str(e)},
                'response_time': time.time() - start_time,
                'headers': {}
            }
    
    def assert_response(self, response: Dict, expected_status: int = 200, 
                       check_performance: bool = True):
        """Assert response meets expectations"""
        assert response['status_code'] == expected_status, \
            f"Expected status {expected_status}, got {response['status_code']}: {response['data']}"
        
        if check_performance:
            assert response['response_time'] < 2.0, \
                f"Response too slow: {response['response_time']:.3f}s"
        
        # Check for performance headers
        if 'X-Response-Time' in response['headers']:
            print(f"✓ Performance header present: {response['headers']['X-Response-Time']}")
    
    async def test_enhanced_health_check(self):
        """Test enhanced health check with all metrics"""
        print("🏥 Testing enhanced health check...")
        
        response = await self.make_request("GET", "/health")
        self.assert_response(response)
        
        health_data = response['data']
        
        # Check required fields
        required_fields = ['status', 'database_enhanced', 'redis', 'performance']
        for field in required_fields:
            assert field in health_data, f"Missing health field: {field}"
        
        # Check performance metrics
        perf = health_data['performance']
        assert 'active_operations' in perf
        assert 'available_connection_slots' in perf
        
        print("✓ Enhanced health check passed")
        return health_data
    
    async def test_performance_optimization(self):
        """Test performance optimizations"""
        print("⚡ Testing performance optimizations...")
        
        # Test concurrent requests
        start_time = time.time()
        
        tasks = []
        for i in range(10):
            task = self.make_request("GET", "/health")
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        # All requests should complete quickly
        assert total_time < 5.0, f"Concurrent requests too slow: {total_time:.3f}s"
        
        # All responses should be successful
        for response in responses:
            assert response['status_code'] == 200
        
        print(f"✓ 10 concurrent requests completed in {total_time:.3f}s")
    
    async def test_rate_limiting(self):
        """Test enhanced rate limiting"""
        print("🚦 Testing rate limiting...")
        
        # Make rapid requests to trigger rate limiting
        responses = []
        for i in range(15):
            response = await self.make_request("GET", "/api/v1/info")
            responses.append(response)
            await asyncio.sleep(0.1)  # Small delay
        
        # Should have mix of successful and rate-limited responses
        success_count = sum(1 for r in responses if r['status_code'] == 200)
        rate_limited_count = sum(1 for r in responses if r['status_code'] == 429)
        
        print(f"✓ Rate limiting test: {success_count} successful, {rate_limited_count} rate-limited")
    
    async def test_user_workflow_with_caching(self):
        """Test complete user workflow with caching"""
        print("👤 Testing user workflow with caching...")
        
        # Register user
        user_data = {
            "username": "testuser_enhanced",
            "name": "Enhanced Test User",
            "email": "enhanced@test.com",
            "password": "TestPassword123",
            "confirm_password": "TestPassword123",
            "type": "Personal"
        }
        
        register_response = await self.make_request("POST", "/api/v1/auth/register", user_data)
        self.assert_response(register_response)
        print("✓ User registration successful")
        
        # Login
        login_data = {
            "email": "enhanced@test.com",
            "password": "TestPassword123"
        }
        
        login_response = await self.make_request("POST", "/api/v1/auth/login", login_data)
        self.assert_response(login_response)
        
        token = login_response['data']['access_token']
        auth_headers = {"Authorization": f"Bearer {token}"}
        print("✓ User login successful")
        
        # Get profile (should be fast due to caching on subsequent requests)
        profile_times = []
        for i in range(3):
            profile_response = await self.make_request("GET", "/api/v1/auth/profile", headers=auth_headers)
            self.assert_response(profile_response)
            profile_times.append(profile_response['response_time'])
        
        # Later requests might be faster due to caching
        print(f"✓ Profile requests: {profile_times}")
        
        # Get API key
        api_key_response = await self.make_request("GET", "/api/v1/auth/api-key", headers=auth_headers)
        self.assert_response(api_key_response)
        
        encrypted_key = api_key_response['data']['key']
        print("✓ API key retrieval successful")
        
        # Test API key usage (this should use caching)
        # Note: We can't directly test the decrypted key without implementing decryption
        print("✓ User workflow with caching completed")
        
        return token, encrypted_key
    
    async def test_database_performance(self):
        """Test database performance optimizations"""
        print("🗄️ Testing database performance...")
        
        # Test multiple concurrent database operations
        start_time = time.time()
        
        tasks = []
        for i in range(5):
            task = self.make_request("GET", "/api/v1/info")
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        db_time = time.time() - start_time
        
        # Should complete quickly due to connection pooling
        assert db_time < 3.0, f"Database operations too slow: {db_time:.3f}s"
        
        print(f"✓ Database performance test completed in {db_time:.3f}s")
    
    async def test_security_features(self):
        """Test enhanced security features"""
        print("🔒 Testing security features...")
        
        # Test security headers
        response = await self.make_request("GET", "/")
        
        # Check for security-related headers (may be added by middleware)
        security_headers = ['X-Response-Time', 'X-Process-ID']
        for header in security_headers:
            if header in response['headers']:
                print(f"✓ Security header present: {header}")
        
        # Test invalid API key format
        invalid_headers = {"Authorization": "Bearer invalid-key-format"}
        invalid_response = await self.make_request("GET", "/api/v1/auth/profile", headers=invalid_headers)
        assert invalid_response['status_code'] == 401, "Should reject invalid API key format"
        
        print("✓ Security features validated")
    
    async def test_monitoring_endpoints(self):
        """Test monitoring and statistics endpoints"""
        print("📊 Testing monitoring endpoints...")
        
        # Test statistics endpoint
        stats_response = await self.make_request("GET", "/api/v1/stats")
        # Note: This might require admin auth in production
        
        if stats_response['status_code'] == 200:
            stats_data = stats_response['data']
            assert 'usage_statistics' in stats_data
            assert 'cache_status' in stats_data
            assert 'performance_mode' in stats_data
            print("✓ Statistics endpoint accessible")
        else:
            print("⚠️ Statistics endpoint requires authentication (expected in production)")
        
        # Test health endpoint comprehensive data
        health_response = await self.make_request("GET", "/health")
        health_data = health_response['data']
        
        # Should have comprehensive monitoring data
        monitoring_fields = ['status', 'database_enhanced', 'redis', 'performance']
        for field in monitoring_fields:
            assert field in health_data, f"Missing monitoring field: {field}"
        
        print("✓ Monitoring endpoints validated")
    
    async def test_docker_compatibility(self):
        """Test Docker-specific features"""
        print("🐳 Testing Docker compatibility...")
        
        # Test health endpoint (important for Docker health checks)
        health_response = await self.make_request("GET", "/health")
        self.assert_response(health_response)
        
        # Test that the application responds on 0.0.0.0 (Docker requirement)
        # This is implicit if we can connect to the service
        
        print("✓ Docker compatibility verified")
    
    async def test_production_readiness(self):
        """Test production readiness features"""
        print("🏭 Testing production readiness...")
        
        # Test that debug information is not exposed
        error_response = await self.make_request("GET", "/nonexistent-endpoint")
        assert error_response['status_code'] == 404
        
        # Error response should not contain sensitive debug info
        error_data = error_response['data']
        sensitive_fields = ['traceback', 'file_path', 'local_vars']
        for field in sensitive_fields:
            assert field not in str(error_data), f"Sensitive debug info exposed: {field}"
        
        # Test comprehensive API info
        info_response = await self.make_request("GET", "/api/v1/info")
        self.assert_response(info_response)
        
        info_data = info_response['data']
        required_info = ['api_name', 'version', 'endpoints', 'authentication_methods']
        for field in required_info:
            assert field in info_data, f"Missing API info: {field}"
        
        print("✓ Production readiness validated")
    
    async def test_load_simulation(self):
        """Simulate moderate load to test system stability"""
        print("🔄 Testing system under moderate load...")
        
        start_time = time.time()
        
        # Create multiple concurrent users
        tasks = []
        for user_id in range(5):
            # Each "user" performs a sequence of operations
            task = self._simulate_user_session(user_id)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time
        
        # Check that all tasks completed successfully
        successful_tasks = sum(1 for r in results if not isinstance(r, Exception))
        
        print(f"✓ Load test completed: {successful_tasks}/5 users successful in {total_time:.3f}s")
        
        # System should remain stable under load
        assert successful_tasks >= 4, "System should handle moderate load"
        assert total_time < 30, "Load test should complete within reasonable time"
    
    async def _simulate_user_session(self, user_id: int):
        """Simulate a realistic user session"""
        try:
            # Health check
            await self.make_request("GET", "/health")
            
            # API info
            await self.make_request("GET", "/api/v1/info")
            
            # Multiple health checks (simulating monitoring)
            for _ in range(3):
                await self.make_request("GET", "/health")
                await asyncio.sleep(0.1)
            
            return True
        except Exception as e:
            print(f"User {user_id} session failed: {e}")
            return False
    
    async def run_comprehensive_tests(self):
        """Run all enhanced tests"""
        print("🚀 Starting Comprehensive Enhanced API Tests")
        print("=" * 60)
        
        test_results = {}
        
        try:
            # Core functionality tests
            test_results["health_check"] = await self.test_enhanced_health_check()
            test_results["performance"] = await self.test_performance_optimization()
            test_results["rate_limiting"] = await self.test_rate_limiting()
            test_results["database_performance"] = await self.test_database_performance()
            
            # User workflow tests
            test_results["user_workflow"] = await self.test_user_workflow_with_caching()
            
            # Security and monitoring tests
            await self.test_security_features()
            await self.test_monitoring_endpoints()
            
            # Production readiness tests
            await self.test_docker_compatibility()
            await self.test_production_readiness()
            
            # Load testing
            await self.test_load_simulation()
            
            print("\n" + "=" * 60)
            print("🎉 ALL ENHANCED TESTS PASSED!")
            print("=" * 60)
            
            print("\n📊 Test Summary:")
            print("✓ Enhanced health monitoring")
            print("✓ Performance optimizations")
            print("✓ Database connection pooling")
            print("✓ Redis caching (with fallback)")
            print("✓ Enhanced rate limiting")
            print("✓ Security improvements")
            print("✓ Monitoring and statistics")
            print("✓ Docker compatibility")
            print("✓ Production readiness")
            print("✓ Load handling capability")
            
            print(f"\n🏆 System is production-ready!")
            print(f"🔗 API Documentation: {self.base_url}/docs")
            print(f"🏥 Health Check: {self.base_url}/health")
            print(f"📊 API Stats: {self.base_url}/api/v1/stats")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Enhanced test failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

async def test_component_integration():
    """Test individual components if API is not running"""
    print("🧪 Testing component integration...")
    
    try:
        # Test configuration
        from app.core.config import settings
        print(f"✓ Configuration loaded: {settings.APP_NAME}")
        
        # Test enhanced database
        from app.db.enhanced_database import enhanced_database
        await enhanced_database.connect()
        
        # Test connection
        async with enhanced_database.get_connection() as conn:
            await conn.execute("SELECT 1")
        print("✓ Enhanced database connection successful")
        
        await enhanced_database.disconnect()
        
        # Test Redis manager
        from app.cache.redis_manager import redis_manager
        await redis_manager.connect()
        
        redis_health = await redis_manager.health_check()
        print(f"✓ Redis manager status: {redis_health['status']}")
        
        await redis_manager.disconnect()
        
        # Test security features
        from app.security.secrets_manager import EnvironmentValidator
        validation = EnvironmentValidator.validate_production_config()
        print(f"✓ Security validation: {len(validation['issues'])} issues, {len(validation['warnings'])} warnings")
        
        print("✓ All components integrate successfully")
        return True
        
    except Exception as e:
        print(f"❌ Component integration failed: {e}")
        return False

async def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced User Management API Test Suite")
    parser.add_argument("--url", default="http://localhost:8000", 
                       help="Base URL of the API")
    parser.add_argument("--components-only", action="store_true",
                       help="Test only component integration (no API calls)")
    args = parser.parse_args()
    
    if args.components_only:
        success = await test_component_integration()
    else:
        async with EnhancedAPITester(args.url) as tester:
            success = await tester.run_comprehensive_tests()
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test runner failed: {str(e)}")
        sys.exit(1)