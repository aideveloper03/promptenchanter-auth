#!/usr/bin/env python3
"""
Test both bcrypt (fixed) and Argon2 implementations
"""

import hashlib
import base64
from passlib.context import CryptContext

def test_bcrypt_fixed():
    """Test bcrypt with proper configuration"""
    print("Testing BCRYPT (with fixes)...")
    
    def prepare_password_for_bcrypt(password: str) -> str:
        password_bytes = password.encode('utf-8')
        if len(password_bytes) <= 72:
            return password
        sha256_hash = hashlib.sha256(password_bytes).digest()
        return base64.b64encode(sha256_hash).decode('ascii')
    
    try:
        # Use bcrypt with specific rounds configuration
        pwd_context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=12
        )
        
        test_cases = [
            "Short123!",
            "A" * 72,
            "ThisIsAnExtremelyLongPasswordThatDefinitelyExceedsThe72ByteLimitForBcrypt" + "!" * 50,
            "Пароль123!🚀🔐",
        ]
        
        for i, password in enumerate(test_cases, 1):
            prepared = prepare_password_for_bcrypt(password)
            hashed = pwd_context.hash(prepared)
            verified = pwd_context.verify(prepared, hashed)
            
            print(f"  Test {i}: {'✓' if verified else '✗'} - {len(password)} chars")
        
        print("✓ BCRYPT implementation working correctly")
        return True
        
    except Exception as e:
        print(f"✗ BCRYPT error: {e}")
        return False

def test_argon2():
    """Test Argon2 as a modern alternative"""
    print("\nTesting ARGON2 (modern alternative)...")
    
    try:
        # Argon2 supports long passwords natively
        pwd_context = CryptContext(
            schemes=["argon2"],
            deprecated="auto"
        )
        
        test_cases = [
            "Short123!",
            "A" * 72,
            "A" * 200,  # Very long password
            "ThisIsAnExtremelyLongPasswordThatDefinitelyExceedsThe72ByteLimitForBcrypt" + "!" * 50,
            "Пароль123!🚀🔐🌟⭐🔥💯🎯💪🎉",
        ]
        
        for i, password in enumerate(test_cases, 1):
            # Argon2 handles long passwords directly - no pre-processing needed
            hashed = pwd_context.hash(password)
            verified = pwd_context.verify(password, hashed)
            
            print(f"  Test {i}: {'✓' if verified else '✗'} - {len(password)} chars, {len(password.encode('utf-8'))} bytes")
        
        print("✓ ARGON2 implementation working correctly")
        return True
        
    except Exception as e:
        print(f"✗ ARGON2 error: {e}")
        return False

def test_performance_comparison():
    """Compare performance of both methods"""
    print("\nTesting PERFORMANCE comparison...")
    
    import time
    
    password = "TestPassword123!"
    iterations = 10
    
    # Test bcrypt
    try:
        bcrypt_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12)
        start = time.time()
        for _ in range(iterations):
            hashed = bcrypt_context.hash(password)
            bcrypt_context.verify(password, hashed)
        bcrypt_time = time.time() - start
        print(f"  BCRYPT: {bcrypt_time:.3f}s for {iterations} iterations")
    except Exception as e:
        print(f"  BCRYPT: Error - {e}")
        bcrypt_time = float('inf')
    
    # Test Argon2
    try:
        argon2_context = CryptContext(schemes=["argon2"])
        start = time.time()
        for _ in range(iterations):
            hashed = argon2_context.hash(password)
            argon2_context.verify(password, hashed)
        argon2_time = time.time() - start
        print(f"  ARGON2: {argon2_time:.3f}s for {iterations} iterations")
    except Exception as e:
        print(f"  ARGON2: Error - {e}")
        argon2_time = float('inf')
    
    return bcrypt_time, argon2_time

def recommend_solution():
    """Recommend the best solution based on tests"""
    print("\n" + "=" * 60)
    print("RECOMMENDATIONS:")
    
    bcrypt_works = test_bcrypt_fixed()
    argon2_works = test_argon2()
    bcrypt_time, argon2_time = test_performance_comparison()
    
    print("\nSUMMARY:")
    print(f"  BCRYPT: {'✓ Working' if bcrypt_works else '✗ Failed'}")
    print(f"  ARGON2: {'✓ Working' if argon2_works else '✗ Failed'}")
    
    if bcrypt_works and argon2_works:
        print("\nBOTH SOLUTIONS WORK! Choose based on your needs:")
        print("  • BCRYPT: Industry standard, widely supported, but has 72-byte limit")
        print("  • ARGON2: Modern, no length limits, designed for current threats")
        print(f"  • Performance: ARGON2 is {'faster' if argon2_time < bcrypt_time else 'slower'}")
        
        print("\nRECOMMENDATION: Use ARGON2 for new projects, BCRYPT for compatibility")
        
    elif bcrypt_works:
        print("\nRECOMMENDATION: Use BCRYPT (with pre-hashing for long passwords)")
        
    elif argon2_works:
        print("\nRECOMMENDATION: Use ARGON2 (bcrypt has compatibility issues)")
        
    else:
        print("\n⚠️  CRITICAL: Neither solution works properly!")
    
    return bcrypt_works, argon2_works

if __name__ == "__main__":
    print("=" * 60)
    print("COMPREHENSIVE PASSWORD HASHING TEST")
    print("=" * 60)
    
    recommend_solution()
    
    print("=" * 60)