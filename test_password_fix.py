#!/usr/bin/env python3
"""
Test script to verify the password hashing fixes work correctly.
"""

import sys
import os
sys.path.append('/workspace')

from app.security.auth import get_password_hash, verify_password, SecurityValidator

def test_password_handling():
    """Test various password scenarios"""
    
    test_cases = [
        # Normal password
        "Admin123!",
        # Long password (within 72 bytes)
        "ThisIsAVeryLongPasswordButStillWithin72BytesForBcryptCompatibility123!",
        # Very long password (exceeds 72 bytes)
        "ThisIsAnExtremelyLongPasswordThatDefinitelyExceedsThe72ByteLimitForBcryptAndWillTriggerPreHashing123!🔐🔑💪",
        # Unicode password
        "Пароль123!🚀",
        # Emoji-heavy password
        "Password123!🔐🔑🚀💪🎉🌟⭐🔥💯🎯"
    ]
    
    print("Testing password hashing with different scenarios...")
    print("=" * 60)
    
    for i, password in enumerate(test_cases, 1):
        print(f"\nTest Case {i}: {password[:20]}{'...' if len(password) > 20 else ''}")
        
        # Get password info
        info = SecurityValidator.get_password_info(password)
        print(f"  Length (chars): {info['length_chars']}")
        print(f"  Length (bytes): {info['length_bytes']}")
        print(f"  Uses pre-hashing: {info['uses_prehashing']}")
        print(f"  Strength: {info['strength_check'][1]}")
        
        # Test hashing and verification
        try:
            hashed = get_password_hash(password)
            verified = verify_password(password, hashed)
            print(f"  Hash generated: ✓")
            print(f"  Verification: {'✓' if verified else '✗'}")
            
            # Test with wrong password
            wrong_verified = verify_password(password + "wrong", hashed)
            print(f"  Wrong password rejected: {'✓' if not wrong_verified else '✗'}")
            
        except Exception as e:
            print(f"  ERROR: {e}")
    
    print("\n" + "=" * 60)
    print("Password handling test completed!")

if __name__ == "__main__":
    test_password_handling()