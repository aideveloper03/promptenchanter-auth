#!/usr/bin/env python3
"""
Basic test script for User Management API
Run this to verify the installation and basic functionality
"""

import asyncio
import aiosqlite
import json
import sys
import os
from datetime import datetime

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from security.auth import (
    verify_password, get_password_hash, generate_api_key,
    encrypt_data, decrypt_data, SecurityValidator
)
from db.database import database
from core.config import settings

async def test_security_functions():
    """Test security and authentication functions"""
    print("🔒 Testing Security Functions...")
    
    # Test password hashing
    password = "testpassword123"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed), "Password verification failed"
    print("✓ Password hashing and verification works")
    
    # Test API key generation
    api_key = generate_api_key()
    assert api_key.startswith("pe-"), "API key format incorrect"
    assert len(api_key) == 35, "API key length incorrect"
    print(f"✓ API key generation works: {api_key}")
    
    # Test encryption/decryption
    data = "sensitive information"
    encrypted = encrypt_data(data)
    decrypted = decrypt_data(encrypted)
    assert decrypted == data, "Encryption/decryption failed"
    print("✓ Data encryption and decryption works")
    
    # Test password validation
    weak_passwords = ["123", "password", "12345678"]
    strong_passwords = ["Password123", "StrongPass1", "MySecure123"]
    
    for pwd in weak_passwords:
        is_strong, _ = SecurityValidator.is_strong_password(pwd)
        assert not is_strong, f"Weak password '{pwd}' incorrectly validated as strong"
    
    for pwd in strong_passwords:
        is_strong, _ = SecurityValidator.is_strong_password(pwd)
        assert is_strong, f"Strong password '{pwd}' incorrectly validated as weak"
    
    print("✓ Password validation works")

async def test_database_operations():
    """Test database operations"""
    print("\n🗄️ Testing Database Operations...")
    
    # Initialize database
    await database.connect()
    await database.init_db()
    print("✓ Database connection and initialization works")
    
    # Test user creation
    test_user_data = {
        'username': 'testuser123',
        'name': 'Test User',
        'email': 'test@example.com',
        'password_hash': get_password_hash('password123'),
        'about_me': 'Test about me',
        'hobbies': 'Testing',
        'type': 'Personal',
        'subscription_plan': 'free',
        'credits': json.dumps({"main": 5, "reset": 5}),
        'limits': json.dumps({"conversation_limit": 10, "reset": 10}),
        'access_rtype': json.dumps(["bpe", "tot"]),
        'level': 'basic',
        'additional_notes': '',
        'key': generate_api_key()
    }
    
    user_id = await database.create_user(test_user_data)
    assert user_id is not None, "User creation failed"
    print(f"✓ User creation works (ID: {user_id})")
    
    # Test user retrieval
    user = await database.get_user_by_email('test@example.com')
    assert user is not None, "User retrieval by email failed"
    assert user['username'] == 'testuser123', "User data incorrect"
    print("✓ User retrieval by email works")
    
    user = await database.get_user_by_username('testuser123')
    assert user is not None, "User retrieval by username failed"
    print("✓ User retrieval by username works")
    
    user = await database.get_user_by_key(test_user_data['key'])
    assert user is not None, "User retrieval by API key failed"
    print("✓ User retrieval by API key works")
    
    # Test conversation limit update
    new_limits = {"conversation_limit": 5, "reset": 10}
    success = await database.update_user_limits('testuser123', new_limits)
    assert success, "Conversation limit update failed"
    
    updated_user = await database.get_user_by_username('testuser123')
    updated_limits = json.loads(updated_user['limits'])
    assert updated_limits['conversation_limit'] == 5, "Limits not updated correctly"
    print("✓ Conversation limit update works")
    
    # Test message logging
    message_data = {
        'username': 'testuser123',
        'email': 'test@example.com',
        'model': 'test-model',
        'messages': [{"role": "user", "content": "test message"}],
        'research_model': False
    }
    
    log_id = await database.log_message(message_data)
    assert log_id is not None, "Message logging failed"
    print(f"✓ Message logging works (Log ID: {log_id})")
    
    # Test admin creation
    admin_id = await database.create_admin('testadmin', get_password_hash('adminpass123'))
    assert admin_id is not None, "Admin creation failed"
    print(f"✓ Admin creation works (ID: {admin_id})")
    
    # Test staff creation
    staff_data = {
        'name': 'Test Staff',
        'username': 'teststaff',
        'email': 'staff@example.com',
        'password_hash': get_password_hash('staffpass123'),
        'staff_level': 'support'
    }
    
    staff_id = await database.create_staff(staff_data)
    assert staff_id is not None, "Staff creation failed"
    print(f"✓ Staff creation works (ID: {staff_id})")
    
    # Test user deletion (soft delete)
    success = await database.delete_user('testuser123', 'test')
    assert success, "User deletion failed"
    
    deleted_user = await database.get_user_by_username('testuser123')
    assert deleted_user is None, "User not properly deleted"
    print("✓ User deletion works")

async def test_configuration():
    """Test configuration loading"""
    print("\n⚙️ Testing Configuration...")
    
    # Test settings
    assert hasattr(settings, 'SECRET_KEY'), "SECRET_KEY not found in settings"
    assert hasattr(settings, 'DATABASE_URL'), "DATABASE_URL not found in settings"
    assert hasattr(settings, 'ADMIN_USERNAME'), "ADMIN_USERNAME not found in settings"
    print("✓ Configuration loading works")
    
    # Test IP whitelist
    test_ips = settings.whitelisted_ips_list
    assert isinstance(test_ips, list), "Whitelisted IPs not parsed correctly"
    print(f"✓ IP whitelist parsing works: {test_ips}")

async def test_batch_operations():
    """Test batch operations"""
    print("\n📦 Testing Batch Operations...")
    
    # Test batch message logging
    logs = []
    for i in range(5):
        logs.append({
            'username': f'user{i}',
            'email': f'user{i}@example.com',
            'model': 'test-model',
            'messages': [{"role": "user", "content": f"test message {i}"}],
            'research_model': False
        })
    
    success = await database.batch_log_messages(logs)
    assert success, "Batch message logging failed"
    print("✓ Batch message logging works")

async def test_daily_reset():
    """Test daily limit reset functionality"""
    print("\n🔄 Testing Daily Reset...")
    
    # Create a test user for reset testing
    test_user_data = {
        'username': 'resetuser',
        'name': 'Reset User',
        'email': 'reset@example.com',
        'password_hash': get_password_hash('password123'),
        'about_me': '',
        'hobbies': '',
        'type': 'Personal',
        'subscription_plan': 'free',
        'credits': json.dumps({"main": 5, "reset": 5}),
        'limits': json.dumps({"conversation_limit": 0, "reset": 10}),
        'access_rtype': json.dumps(["bpe", "tot"]),
        'level': 'basic',
        'additional_notes': '',
        'key': generate_api_key()
    }
    
    await database.create_user(test_user_data)
    
    # Test reset function
    await database.reset_daily_limits()
    
    # Check if limits were reset
    user = await database.get_user_by_username('resetuser')
    limits = json.loads(user['limits'])
    assert limits['conversation_limit'] == 10, "Daily reset failed"
    print("✓ Daily limit reset works")
    
    # Cleanup
    await database.delete_user('resetuser', 'test')

def print_summary():
    """Print test summary and next steps"""
    print("\n" + "="*60)
    print("🎉 ALL TESTS PASSED!")
    print("="*60)
    print("\nYour User Management API is ready to use!")
    print("\nNext steps:")
    print("1. Copy .env.example to .env and configure your settings")
    print("2. Run the API: python main.py")
    print("3. Access documentation: http://localhost:8000/docs")
    print("4. Test health endpoint: http://localhost:8000/health")
    print("\nDefault admin credentials:")
    print(f"   Username: {settings.ADMIN_USERNAME}")
    print(f"   Password: {settings.ADMIN_PASSWORD}")
    print("\nSecurity reminder:")
    print("- Change SECRET_KEY and ENCRYPTION_KEY in production")
    print("- Use strong admin password")
    print("- Enable IP whitelisting for production")
    print("- Set up SSL/TLS encryption")

async def cleanup_test_data():
    """Clean up test data"""
    print("\n🧹 Cleaning up test data...")
    
    try:
        # Clean up any remaining test users
        await database.delete_user('testuser123', 'cleanup')
        await database.delete_user('resetuser', 'cleanup')
        
        # Note: In a real cleanup, you might want to delete from deleted_users table too
        # But for testing, we'll leave the soft-deleted records
        
        print("✓ Test data cleaned up")
    except Exception as e:
        print(f"⚠️ Cleanup warning: {str(e)}")

async def main():
    """Run all tests"""
    print("🚀 Starting User Management API Tests")
    print("=====================================")
    
    try:
        await test_configuration()
        await test_security_functions()
        await test_database_operations()
        await test_batch_operations()
        await test_daily_reset()
        await cleanup_test_data()
        
        print_summary()
        
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        # Clean up database connection
        await database.disconnect()

if __name__ == "__main__":
    # Run tests
    asyncio.run(main())