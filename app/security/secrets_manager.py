import os
import base64
import secrets
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)

class SecretsManager:
    """Enhanced secrets management for production security"""
    
    def __init__(self):
        self._encryption_key = None
        self._initialized = False
    
    def initialize(self, master_key: str = None):
        """Initialize secrets manager with master key"""
        if self._initialized:
            return
        
        if master_key:
            # Use provided master key
            self._encryption_key = self._derive_key_from_password(master_key)
        else:
            # Use environment variable or generate
            env_key = os.getenv('ENCRYPTION_KEY')
            if env_key:
                if len(env_key) == 44:  # Base64 encoded key
                    try:
                        self._encryption_key = env_key.encode()
                        # Test if it's a valid Fernet key
                        Fernet(self._encryption_key)
                    except Exception:
                        # If invalid, derive from password
                        self._encryption_key = self._derive_key_from_password(env_key)
                else:
                    # Derive key from password
                    self._encryption_key = self._derive_key_from_password(env_key)
            else:
                # Generate a new key (for development only)
                logger.warning("No ENCRYPTION_KEY found, generating temporary key")
                self._encryption_key = Fernet.generate_key()
        
        self._initialized = True
    
    def _derive_key_from_password(self, password: str) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        # Use a fixed salt for consistency (in production, use a stored salt)
        salt = b'user_management_salt_2024'  # In production, store this securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self._initialized:
            self.initialize()
        
        fernet = Fernet(self._encryption_key)
        return fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self._initialized:
            self.initialize()
        
        fernet = Fernet(self._encryption_key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def generate_api_key(self) -> str:
        """Generate secure API key with proper format"""
        return f"pe-{secrets.token_urlsafe(24)}"  # 32 chars total with prefix
    
    def hash_password(self, password: str) -> str:
        """Hash password securely"""
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return pwd_context.hash(password)
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return pwd_context.verify(password, hashed)

class EnvironmentValidator:
    """Validate and secure environment configuration"""
    
    @staticmethod
    def validate_production_config() -> Dict[str, Any]:
        """Validate production configuration and return issues"""
        issues = []
        warnings = []
        
        # Check SECRET_KEY
        secret_key = os.getenv('SECRET_KEY', '')
        if secret_key == 'your-super-secret-key-here-change-this-in-production':
            issues.append("SECRET_KEY is using default value - MUST be changed for production")
        elif len(secret_key) < 32:
            issues.append("SECRET_KEY is too short - should be at least 32 characters")
        
        # Check ENCRYPTION_KEY
        encryption_key = os.getenv('ENCRYPTION_KEY', '')
        if encryption_key == 'your-encryption-key-here-32-bytes':
            issues.append("ENCRYPTION_KEY is using default value - MUST be changed for production")
        elif len(encryption_key) < 32:
            warnings.append("ENCRYPTION_KEY should be at least 32 characters for optimal security")
        
        # Check ADMIN_PASSWORD
        admin_password = os.getenv('ADMIN_PASSWORD', '')
        if admin_password == 'admin123!':
            issues.append("ADMIN_PASSWORD is using default value - MUST be changed for production")
        elif len(admin_password) < 12:
            warnings.append("ADMIN_PASSWORD should be at least 12 characters")
        
        # Check DEBUG mode
        debug = os.getenv('DEBUG', '').lower()
        if debug in ['true', '1', 'yes']:
            warnings.append("DEBUG mode is enabled - should be disabled in production")
        
        # Check IP whitelisting
        ip_whitelist = os.getenv('ENABLE_IP_WHITELIST', '').lower()
        if ip_whitelist not in ['true', '1', 'yes']:
            warnings.append("IP whitelisting is disabled - consider enabling for production")
        
        # Check database configuration
        db_url = os.getenv('DATABASE_URL', '')
        if db_url.startswith('sqlite:'):
            warnings.append("Using SQLite - consider PostgreSQL for production scalability")
        
        return {
            'issues': issues,
            'warnings': warnings,
            'is_production_ready': len(issues) == 0
        }
    
    @staticmethod
    def generate_secure_config() -> Dict[str, str]:
        """Generate secure configuration values"""
        return {
            'SECRET_KEY': secrets.token_urlsafe(64),
            'ENCRYPTION_KEY': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            'ADMIN_PASSWORD': secrets.token_urlsafe(16),
            'JWT_SECRET': secrets.token_urlsafe(32)
        }

class SecurityHeaders:
    """Security headers for production deployment"""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get recommended security headers"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'"
            ),
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': (
                "geolocation=(), "
                "microphone=(), "
                "camera=(), "
                "payment=(), "
                "usb=(), "
                "magnetometer=(), "
                "gyroscope=(), "
                "accelerometer=()"
            )
        }

# Global secrets manager instance
secrets_manager = SecretsManager()

# Initialize on import
secrets_manager.initialize()