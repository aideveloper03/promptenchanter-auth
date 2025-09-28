import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
from cryptography.fernet import Fernet
import base64
import hashlib

from ..core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Encryption setup
def get_encryption_key() -> bytes:
    """Generate or get encryption key"""
    key = settings.ENCRYPTION_KEY.encode()
    # Ensure key is 32 bytes for Fernet
    key = hashlib.sha256(key).digest()
    return base64.urlsafe_b64encode(key)

fernet = Fernet(get_encryption_key())

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)

def generate_api_key() -> str:
    """Generate a unique API key"""
    # Generate 32 random characters
    chars = string.ascii_letters + string.digits
    random_part = ''.join(secrets.choice(chars) for _ in range(32))
    return f"pe-{random_part}"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data"""
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    return fernet.decrypt(encrypted_data.encode()).decode()

def validate_ip_address(ip: str) -> bool:
    """Validate if IP is whitelisted"""
    if not settings.ENABLE_IP_WHITELIST:
        return True
    
    whitelisted_ips = settings.whitelisted_ips_list
    
    # Handle localhost variations
    localhost_variants = ["127.0.0.1", "localhost", "::1"]
    if ip in localhost_variants and any(variant in whitelisted_ips for variant in localhost_variants):
        return True
    
    return ip in whitelisted_ips

class SecurityValidator:
    """Security validation utilities"""
    
    @staticmethod
    def validate_api_key_format(key: str) -> bool:
        """Validate API key format"""
        if not key.startswith("pe-"):
            return False
        if len(key) != 35:  # pe- + 32 characters
            return False
        return True
    
    @staticmethod
    def is_strong_password(password: str) -> tuple[bool, str]:
        """Check if password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least 1 number"
        
        if not any(c.isupper() for c in password):
            return False, "Password should contain at least 1 uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password should contain at least 1 lowercase letter"
        
        return True, "Password is strong"
    
    @staticmethod
    def sanitize_input(data: str, max_length: int = 1000) -> str:
        """Sanitize user input"""
        if not data:
            return ""
        
        # Remove potential XSS characters
        dangerous_chars = ["<", ">", "&", "\"", "'", "/"]
        for char in dangerous_chars:
            data = data.replace(char, "")
        
        # Truncate if too long
        return data[:max_length].strip()