import os
from typing import List, Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Security
    SECRET_KEY: str = "your-super-secret-key-here-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str = "sqlite:///./user_management.db"
    
    # Security Settings
    BCRYPT_ROUNDS: int = 12
    ENCRYPTION_KEY: str = "your-encryption-key-here-32-bytes"
    
    # Email Settings (Optional)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    
    # Admin Settings
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "Admin123!"
    
    # IP Whitelisting
    ENABLE_IP_WHITELIST: bool = False
    WHITELISTED_IPS: str = "127.0.0.1,localhost"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Message Logging
    BATCH_LOG_INTERVAL_MINUTES: int = 10
    MEMORY_THRESHOLD_MB: int = 1024
    
    # Redis Settings
    REDIS_URL: str = "redis://redis:6379/0"
    
    # Application Settings
    APP_NAME: str = "User Management API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    @property
    def whitelisted_ips_list(self) -> List[str]:
        return [ip.strip() for ip in self.WHITELISTED_IPS.split(",")]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()