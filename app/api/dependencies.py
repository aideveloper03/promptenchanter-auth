from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any
import json

from ..db.mongodb_database import mongodb_database as database
from ..security.auth import verify_token, validate_ip_address
from ..core.config import settings

security = HTTPBearer()

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get current user from JWT token"""
    # Validate IP if whitelisting is enabled
    client_ip = request.client.host
    if not validate_ip_address(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not whitelisted"
        )
    
    # Verify token
    payload = verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = await database.get_user_by_username(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

async def get_current_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get current admin from JWT token"""
    # Validate IP if whitelisting is enabled
    client_ip = request.client.host
    if not validate_ip_address(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not whitelisted"
        )
    
    # Verify token
    payload = verify_token(credentials.credentials)
    if payload is None or payload.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin access required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    admin = await database.get_admin_by_username(username)
    if admin is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return admin

async def get_current_staff(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get current staff from JWT token"""
    # Validate IP if whitelisting is enabled
    client_ip = request.client.host
    if not validate_ip_address(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not whitelisted"
        )
    
    # Verify token
    payload = verify_token(credentials.credentials)
    if payload is None or payload.get("role") != "staff":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Staff access required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    staff = await database.get_staff_by_username(username)
    if staff is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Staff not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return staff

async def verify_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Verify API key and deduct conversation limit"""
    # Validate IP if whitelisting is enabled
    client_ip = request.client.host
    if not validate_ip_address(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not whitelisted"
        )
    
    api_key = credentials.credentials
    
    # Try to decrypt the API key if it's encrypted
    try:
        from ..security.auth import decrypt_data
        decrypted_key = decrypt_data(api_key)
        # Validate the decrypted key format
        from ..security.auth import SecurityValidator
        if SecurityValidator.validate_api_key_format(decrypted_key):
            api_key = decrypted_key
    except:
        # If decryption fails, try using the key as-is (for raw keys)
        pass
    
    # Get user by API key
    user = await database.get_user_by_key(api_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check conversation limits
    limits = user['limits'] if isinstance(user['limits'], dict) else json.loads(user['limits'])
    if limits.get('conversation_limit', 0) <= 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Conversation limit exceeded. Limit resets every 24 hours."
        )
    
    # Deduct conversation limit
    limits['conversation_limit'] -= 1
    await database.update_user_limits(user['username'], limits)
    
    return user

def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> Optional[Dict[str, Any]]:
    """Get user if token is provided, otherwise return None"""
    if credentials is None:
        return None
    
    try:
        # Validate IP if whitelisting is enabled
        client_ip = request.client.host
        if not validate_ip_address(client_ip):
            return None
        
        payload = verify_token(credentials.credentials)
        if payload is None:
            return None
        
        username: str = payload.get("sub")
        if username is None:
            return None
        
        # This is a sync call, you might want to make it async
        return None  # For now, return None - implement async version if needed
    except:
        return None