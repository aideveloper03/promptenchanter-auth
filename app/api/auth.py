from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from datetime import timedelta
import json
from typing import Dict, Any

from ..models.user import UserCreate, UserLogin, UserResponse, KeyResponse, PasswordReset, EmailUpdate
from ..models.message import MessageLogCreate, MessageLogRequest
from ..db.enhanced_database import enhanced_database as database
from ..security.auth import (
    verify_password, get_password_hash, create_access_token, 
    generate_api_key, encrypt_data, decrypt_data, SecurityValidator
)
from ..core.config import settings
from .dependencies import get_current_user, verify_api_key

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=Dict[str, str], status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, request: Request):
    """Register a new user"""
    try:
        # Validate IP if whitelisting is enabled
        from ..security.auth import validate_ip_address
        client_ip = request.client.host
        if not validate_ip_address(client_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address not whitelisted"
            )
        
        # Sanitize inputs
        user.username = SecurityValidator.sanitize_input(user.username, 30)
        user.name = SecurityValidator.sanitize_input(user.name, 100)
        user.about_me = SecurityValidator.sanitize_input(user.about_me, 500)
        user.hobbies = SecurityValidator.sanitize_input(user.hobbies, 500)
        
        # Check if user already exists
        existing_user_email = await database.get_user_by_email(user.email)
        if existing_user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        existing_user_username = await database.get_user_by_username(user.username)
        if existing_user_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        
        # Additional password validation
        is_strong, message = SecurityValidator.is_strong_password(user.password)
        if not is_strong:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        # Hash password
        password_hash = get_password_hash(user.password)
        
        # Generate unique API key
        api_key = generate_api_key()
        
        # Ensure API key is unique
        while await database.get_user_by_key(api_key):
            api_key = generate_api_key()
        
        # Prepare user data
        user_data = {
            'username': user.username,
            'name': user.name,
            'email': user.email,
            'password_hash': password_hash,
            'about_me': user.about_me,
            'hobbies': user.hobbies,
            'type': user.type,
            'subscription_plan': 'free',
            'credits': json.dumps({"main": 5, "reset": 5}),
            'limits': json.dumps({"conversation_limit": 10, "reset": 10}),
            'access_rtype': json.dumps(["bpe", "tot"]),
            'level': 'basic',
            'additional_notes': '',
            'key': api_key
        }
        
        # Create user
        user_id = await database.create_user(user_data)
        if user_id:
            return {
                "message": "User registered successfully",
                "user_id": str(user_id),
                "username": user.username
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/login", response_model=Dict[str, str])
async def login_user(user_login: UserLogin, request: Request):
    """Login user and return access token"""
    try:
        # Validate IP if whitelisting is enabled
        from ..security.auth import validate_ip_address
        client_ip = request.client.host
        if not validate_ip_address(client_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address not whitelisted"
            )
        
        # Get user
        user = await database.get_user_by_email(user_login.email)
        if not user or not verify_password(user_login.password, user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user['username'], "role": "user"},
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": str(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@router.get("/profile", response_model=UserResponse)
async def get_user_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user profile"""
    try:
        return UserResponse(
            username=current_user['username'],
            name=current_user['name'],
            email=current_user['email'],
            about_me=current_user['about_me'],
            hobbies=current_user['hobbies'],
            type=current_user['type'],
            time_created=current_user['time_created'],
            subscription_plan=current_user['subscription_plan'],
            credits=json.loads(current_user['credits']),
            limits=json.loads(current_user['limits']),
            access_rtype=json.loads(current_user['access_rtype']),
            level=current_user['level'],
            additional_notes=current_user['additional_notes']
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get profile: {str(e)}"
        )

@router.get("/api-key", response_model=KeyResponse)
async def get_api_key(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get user's encrypted API key"""
    try:
        encrypted_key = encrypt_data(current_user['key'])
        return KeyResponse(
            key=encrypted_key,
            created_at=current_user['time_created']
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get API key: {str(e)}"
        )

@router.post("/regenerate-key", response_model=KeyResponse)
async def regenerate_api_key(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Regenerate user's API key"""
    try:
        # Generate new unique API key
        new_api_key = generate_api_key()
        
        # Ensure API key is unique
        while await database.get_user_by_key(new_api_key):
            new_api_key = generate_api_key()
        
        # Update user's key
        success = await database.update_user_key(current_user['username'], new_api_key)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update API key"
            )
        
        encrypted_key = encrypt_data(new_api_key)
        return KeyResponse(
            key=encrypted_key,
            created_at=current_user['time_created']
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to regenerate API key: {str(e)}"
        )

@router.put("/profile", response_model=Dict[str, str])
async def update_user_profile(
    update_data: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update user profile"""
    try:
        # Allowed fields for user update
        allowed_fields = ['name', 'about_me', 'hobbies']
        filtered_data = {k: v for k, v in update_data.items() if k in allowed_fields}
        
        if not filtered_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid fields to update"
            )
        
        # Sanitize inputs
        for key, value in filtered_data.items():
            if isinstance(value, str):
                max_length = 100 if key == 'name' else 500
                filtered_data[key] = SecurityValidator.sanitize_input(value, max_length)
        
        success = await database.update_user_profile(current_user['username'], filtered_data)
        if success:
            return {"message": "Profile updated successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update profile"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}"
        )

@router.put("/password", response_model=Dict[str, str])
async def reset_password(
    password_reset: PasswordReset,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Reset user password"""
    try:
        # Verify current password
        if not verify_password(password_reset.current_password, current_user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Additional password validation
        is_strong, message = SecurityValidator.is_strong_password(password_reset.new_password)
        if not is_strong:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        # Hash new password
        new_password_hash = get_password_hash(password_reset.new_password)
        
        # Update password
        success = await database.update_user_profile(
            current_user['username'], 
            {'password_hash': new_password_hash}
        )
        
        if success:
            return {"message": "Password updated successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update password: {str(e)}"
        )

@router.delete("/account", response_model=Dict[str, str])
async def delete_account(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Delete user account"""
    try:
        print(f"Attempting to delete user: {current_user['username']}")
        success = await database.delete_user(current_user['username'], "user")
        print(f"Delete result: {success}")
        if success:
            return {"message": "Account deleted successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete account - database operation returned False"
            )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Exception during delete: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete account: {str(e)}"
        )

# API Key verification endpoint for middleware
@router.post("/verify-key", response_model=Dict[str, Any])
async def verify_api_key_endpoint(
    request: Request,
    current_user: Dict[str, Any] = Depends(verify_api_key)
):
    """Verify API key and deduct conversation limit (for middleware use)"""
    return {
        "valid": True,
        "username": current_user['username'],
        "email": current_user['email'],
        "remaining_conversations": json.loads(current_user['limits']).get('conversation_limit', 0)
    }

# Message logging endpoint
@router.post("/log-message", response_model=Dict[str, str])
async def log_message(
    message_data: MessageLogRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(verify_api_key)
):
    """Log a message (used by external APIs)"""
    try:
        log_data = {
            'username': current_user['username'],
            'email': current_user['email'],
            'model': message_data.model,
            'messages': message_data.messages,
            'research_model': message_data.research_model
        }
        
        log_id = await database.log_message(log_data)
        if log_id:
            return {"message": "Message logged successfully", "log_id": str(log_id)}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to log message"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to log message: {str(e)}"
        )