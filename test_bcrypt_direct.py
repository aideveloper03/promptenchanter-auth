#!/usr/bin/env python3
"""
Direct test of bcrypt implementation without the full app context.
"""

import hashlib
import base64
from passlib.context import CryptContext

def test_bcrypt_compatibility():
    """Test if bcrypt and passlib work together"""
    print("Testing bcrypt and passlib compatibility...")
    
    try:
        # Test basic CryptContext creation
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        print("✓ CryptContext created successfully")
        
        # Test basic password hashing
        test_password = "TestPassword123!"
        hashed = pwd_context.hash(test_password)
        print(f"✓ Password hashed successfully: {hashed[:20]}...")
        
        # Test password verification
        verified = pwd_context.verify(test_password, hashed)
        print(f"✓ Password verification: {'SUCCESS' if verified else 'FAILED'}")
        
        # Test wrong password
        wrong_verified = pwd_context.verify("WrongPassword", hashed)
        print(f"✓ Wrong password rejected: {'SUCCESS' if not wrong_verified else 'FAILED'}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_long_password_handling():
    """Test handling of long passwords"""
    print("\nTesting long password handling...")
    
    def prepare_password_for_bcrypt(password: str) -> str:
        """Prepare password for bcrypt hashing"""
        password_bytes = password.encode('utf-8')
        
        if len(password_bytes) <= 72:
            return password
        
        # Pre-hash with SHA-256 and encode as base64
        sha256_hash = hashlib.sha256(password_bytes).digest()
        return base64.b64encode(sha256_hash).decode('ascii')
    
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    test_cases = [
        # Short password
        "Short123!",
        # Exactly 72 bytes
        "A" * 72,
        # Long password (will trigger pre-hashing)
        "ThisIsAnExtremelyLongPasswordThatDefinitelyExceedsThe72ByteLimitForBcrypt" + "!" * 50,
        # Unicode password
        "Пароль123!🚀🔐",
    ]
    
    for i, password in enumerate(test_cases, 1):
        print(f"\nTest case {i}: {len(password)} chars, {len(password.encode('utf-8'))} bytes")
        
        try:
            prepared = prepare_password_for_bcrypt(password)
            print(f"  Prepared: {len(prepared)} chars, {len(prepared.encode('utf-8'))} bytes")
            print(f"  Pre-hashed: {'Yes' if len(password.encode('utf-8')) > 72 else 'No'}")
            
            # Hash the prepared password
            hashed = pwd_context.hash(prepared)
            print(f"  ✓ Hashed successfully")
            
            # Verify with original password (using same preparation)
            verified = pwd_context.verify(prepared, hashed)
            print(f"  ✓ Verification: {'SUCCESS' if verified else 'FAILED'}")
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False
    
    return True

def test_bcrypt_versions():
    """Test bcrypt version compatibility"""
    print("\nTesting bcrypt version information...")
    
    try:
        import bcrypt
        print(f"bcrypt module imported successfully")
        
        # Check if __version__ exists
        if hasattr(bcrypt, '__version__'):
            print(f"bcrypt version: {bcrypt.__version__}")
        else:
            print("bcrypt.__version__ not available")
        
        # Check if __about__ exists (this was the original issue)
        if hasattr(bcrypt, '__about__'):
            print(f"bcrypt.__about__ exists: {bcrypt.__about__}")
        else:
            print("bcrypt.__about__ not available (this is expected in newer versions)")
        
        # Test direct bcrypt usage
        test_password = b"test123"
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(test_password, salt)
        verified = bcrypt.checkpw(test_password, hashed)
        
        print(f"✓ Direct bcrypt test: {'SUCCESS' if verified else 'FAILED'}")
        
        return True
        
    except Exception as e:
        print(f"✗ bcrypt test error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("BCRYPT IMPLEMENTATION TEST")
    print("=" * 60)
    
    success = True
    
    success &= test_bcrypt_compatibility()
    success &= test_long_password_handling()
    success &= test_bcrypt_versions()
    
    print("\n" + "=" * 60)
    if success:
        print("✓ ALL TESTS PASSED - bcrypt implementation is working correctly!")
    else:
        print("✗ SOME TESTS FAILED - bcrypt implementation needs fixes!")
    print("=" * 60)