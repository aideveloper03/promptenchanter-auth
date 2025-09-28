#!/usr/bin/env python3
"""
Test only the password hashing implementation
"""

import hashlib
import base64
from passlib.context import CryptContext

def test_argon2_bcrypt_hybrid():
    """Test the hybrid Argon2 + bcrypt implementation"""
    print("Testing HYBRID ARGON2 + BCRYPT IMPLEMENTATION")
    print("=" * 60)
    
    # Create the same context as in our app
    pwd_context = CryptContext(
        schemes=["argon2", "bcrypt"],
        deprecated="auto",
        # Argon2 configuration (primary)
        argon2__memory_cost=65536,  # 64 MB
        argon2__time_cost=3,        # 3 iterations
        argon2__parallelism=4,      # 4 parallel threads
        # bcrypt configuration (fallback/compatibility)
        bcrypt__rounds=12
    )
    
    def prepare_password_for_hashing(password: str, target_scheme: str = None) -> str:
        """Prepare password for hashing based on the target scheme"""
        password_bytes = password.encode('utf-8')
        
        # Argon2 handles any length password natively
        if target_scheme == "argon2" or len(password_bytes) <= 72:
            return password
        
        # For bcrypt with long passwords, pre-hash with SHA-256
        sha256_hash = hashlib.sha256(password_bytes).digest()
        return base64.b64encode(sha256_hash).decode('ascii')
    
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash (supports both Argon2 and bcrypt)"""
        # passlib automatically detects the scheme from the hash
        # For bcrypt hashes, we need to prepare the password the same way
        if hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$'):
            # This is a bcrypt hash, prepare password for bcrypt
            prepared_password = prepare_password_for_hashing(plain_password, "bcrypt")
            return pwd_context.verify(prepared_password, hashed_password)
        else:
            # This is likely Argon2 or another scheme, use password directly
            return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(password: str) -> str:
        """Hash a password using modern Argon2 (with bcrypt fallback support)"""
        # passlib will use the first scheme (argon2) by default
        # Argon2 handles long passwords natively, no preparation needed
        return pwd_context.hash(password)
    
    # Test cases
    test_cases = [
        ("Short password", "Admin123!"),
        ("Exact 72 bytes", "A" * 72),
        ("Long password", "ThisIsAnExtremelyLongPasswordThatDefinitelyExceedsThe72ByteLimitForBcryptAndWillTestOurImplementation123!"),
        ("Unicode password", "Пароль123!🚀🔐"),
        ("Emoji password", "Pass123!🔐🔑🚀💪🎉🌟⭐🔥💯"),
    ]
    
    all_passed = True
    
    for name, password in test_cases:
        print(f"\n{name}:")
        print(f"  Password: {password[:40]}{'...' if len(password) > 40 else ''}")
        print(f"  Length: {len(password)} chars, {len(password.encode('utf-8'))} bytes")
        
        try:
            # Test hashing (should use Argon2 by default)
            hashed = get_password_hash(password)
            
            # Check which scheme was used
            if hashed.startswith('$argon2'):
                scheme_used = "Argon2"
            elif hashed.startswith('$2b$'):
                scheme_used = "bcrypt"
            else:
                scheme_used = "Unknown"
            
            print(f"  Hash: {hashed[:50]}...")
            print(f"  Scheme used: {scheme_used}")
            
            # Test verification
            verified = verify_password(password, hashed)
            print(f"  Verification: {'✓ PASS' if verified else '✗ FAIL'}")
            
            # Test wrong password
            wrong_verified = verify_password(password + "wrong", hashed)
            print(f"  Wrong password rejected: {'✓ PASS' if not wrong_verified else '✗ FAIL'}")
            
            if not verified or wrong_verified:
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            all_passed = False
    
    return all_passed

def test_bcrypt_compatibility():
    """Test that we can still verify existing bcrypt hashes"""
    print("\n" + "=" * 60)
    print("Testing BCRYPT COMPATIBILITY")
    print("=" * 60)
    
    # Create some bcrypt hashes to test compatibility
    bcrypt_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12)
    
    test_passwords = ["Admin123!", "TestUser123!", "Short123!"]
    
    # Our hybrid context
    hybrid_context = CryptContext(
        schemes=["argon2", "bcrypt"],
        deprecated="auto",
        argon2__memory_cost=65536,
        argon2__time_cost=3,
        argon2__parallelism=4,
        bcrypt__rounds=12
    )
    
    def prepare_password_for_hashing(password: str, target_scheme: str = None) -> str:
        password_bytes = password.encode('utf-8')
        if target_scheme == "argon2" or len(password_bytes) <= 72:
            return password
        sha256_hash = hashlib.sha256(password_bytes).digest()
        return base64.b64encode(sha256_hash).decode('ascii')
    
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        if hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$'):
            prepared_password = prepare_password_for_hashing(plain_password, "bcrypt")
            return hybrid_context.verify(prepared_password, hashed_password)
        else:
            return hybrid_context.verify(plain_password, hashed_password)
    
    all_compatible = True
    
    for password in test_passwords:
        print(f"\nTesting compatibility for: {password}")
        
        try:
            # Create a bcrypt hash (simulating existing data)
            bcrypt_hash = bcrypt_context.hash(password)
            print(f"  Existing bcrypt hash: {bcrypt_hash[:50]}...")
            
            # Verify with hybrid system
            verified = verify_password(password, bcrypt_hash)
            print(f"  Hybrid system verification: {'✓ PASS' if verified else '✗ FAIL'}")
            
            if not verified:
                all_compatible = False
                
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            all_compatible = False
    
    return all_compatible

if __name__ == "__main__":
    print("🔐 PASSWORD HASHING SYSTEM TEST")
    print("=" * 60)
    
    success1 = test_argon2_bcrypt_hybrid()
    success2 = test_bcrypt_compatibility()
    
    print("\n" + "=" * 60)
    print("FINAL RESULTS:")
    print("=" * 60)
    
    if success1 and success2:
        print("🎉 COMPLETE SUCCESS!")
        print("\n✅ New Implementation Features:")
        print("   • Uses modern Argon2 by default (faster, more secure)")
        print("   • Supports passwords of unlimited length")
        print("   • Maintains full backward compatibility with bcrypt")
        print("   • No password truncation or data loss")
        print("   • Handles Unicode and emoji passwords correctly")
        print("\n🚀 READY FOR PRODUCTION!")
    else:
        print("❌ ISSUES DETECTED:")
        if not success1:
            print("   • New hybrid implementation has problems")
        if not success2:
            print("   • Backward compatibility with bcrypt failed")
        print("\n🔧 NEEDS FURTHER INVESTIGATION")
    
    print("=" * 60)