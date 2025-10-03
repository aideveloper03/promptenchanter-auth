from fastapi import APIRouter, HTTPException, status, Depends, Request, Query
from datetime import timedelta
import json
from typing import Dict, Any, List, Optional

from ..models.admin import AdminLogin, AdminUserUpdate, StaffCreate, StaffResponse
from ..models.user import UserResponse
from ..db.enhanced_database import enhanced_database as database
from ..security.auth import (
    verify_password, get_password_hash, create_access_token, 
    generate_api_key, SecurityValidator
)
from ..core.config import settings
from .dependencies import get_current_admin

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.post("/login", response_model=Dict[str, str])
async def admin_login(admin_login: AdminLogin, request: Request):
    """Admin login"""
    try:
        # Validate IP if whitelisting is enabled
        from ..security.auth import validate_ip_address
        client_ip = request.client.host
        if not validate_ip_address(client_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address not whitelisted"
            )
        
        # Get admin
        admin = await database.get_admin_by_username(admin_login.username)
        if not admin or not verify_password(admin_login.password, admin['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": admin['username'], "role": "admin"},
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
            detail=f"Admin login failed: {str(e)}"
        )

@router.get("/users", response_model=List[UserResponse])
async def get_all_users(
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Get all users (paginated)"""
    try:
        users_data = await database.get_all_users(limit, offset)
        users = []
        
        for user_data in users_data:
            user = UserResponse(
                username=user_data['username'],
                name=user_data['name'],
                email=user_data['email'],
                about_me=user_data['about_me'],
                hobbies=user_data['hobbies'],
                type=user_data['type'],
                time_created=user_data['time_created'],
                subscription_plan=user_data['subscription_plan'],
                credits=json.loads(user_data['credits']),
                limits=json.loads(user_data['limits']),
                access_rtype=json.loads(user_data['access_rtype']),
                level=user_data['level'],
                additional_notes=user_data['additional_notes']
            )
            users.append(user)
        
        return users
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get users: {str(e)}"
        )

@router.get("/users/{username}", response_model=UserResponse)
async def get_user_by_username(
    username: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Get specific user by username"""
    try:
        user_data = await database.get_user_by_username(username)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserResponse(
            username=user_data['username'],
            name=user_data['name'],
            email=user_data['email'],
            about_me=user_data['about_me'],
            hobbies=user_data['hobbies'],
            type=user_data['type'],
            time_created=user_data['time_created'],
            subscription_plan=user_data['subscription_plan'],
            credits=json.loads(user_data['credits']),
            limits=json.loads(user_data['limits']),
            access_rtype=json.loads(user_data['access_rtype']),
            level=user_data['level'],
            additional_notes=user_data['additional_notes']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get user: {str(e)}"
        )

@router.put("/users/{username}", response_model=Dict[str, str])
async def update_user(
    username: str,
    update_data: AdminUserUpdate,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Update user information (admin only)"""
    try:
        # Check if user exists
        user = await database.get_user_by_username(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prepare update data
        update_dict = {}
        
        if update_data.name is not None:
            update_dict['name'] = SecurityValidator.sanitize_input(update_data.name, 100)
        
        if update_data.email is not None:
            # Check if email is already taken by another user
            existing_user = await database.get_user_by_email(update_data.email)
            if existing_user and existing_user['username'] != username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already taken by another user"
                )
            update_dict['email'] = update_data.email
        
        if update_data.about_me is not None:
            update_dict['about_me'] = SecurityValidator.sanitize_input(update_data.about_me, 500)
        
        if update_data.hobbies is not None:
            update_dict['hobbies'] = SecurityValidator.sanitize_input(update_data.hobbies, 500)
        
        if update_data.type is not None:
            update_dict['type'] = update_data.type
        
        if update_data.subscription_plan is not None:
            update_dict['subscription_plan'] = update_data.subscription_plan
        
        if update_data.credits is not None:
            update_dict['credits'] = json.dumps(update_data.credits)
        
        if update_data.limits is not None:
            update_dict['limits'] = json.dumps(update_data.limits)
        
        if update_data.access_rtype is not None:
            update_dict['access_rtype'] = json.dumps(update_data.access_rtype)
        
        if update_data.level is not None:
            update_dict['level'] = update_data.level
        
        if update_data.additional_notes is not None:
            update_dict['additional_notes'] = SecurityValidator.sanitize_input(update_data.additional_notes, 1000)
        
        if update_data.is_active is not None:
            update_dict['is_active'] = update_data.is_active
        
        if not update_dict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid fields to update"
            )
        
        success = await database.update_user_profile(username, update_dict)
        if success:
            return {"message": "User updated successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user: {str(e)}"
        )

@router.delete("/users/{username}", response_model=Dict[str, str])
async def delete_user(
    username: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Delete user account (admin only)"""
    try:
        success = await database.delete_user(username, f"admin:{current_admin['username']}")
        if success:
            return {"message": "User deleted successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}"
        )

@router.post("/users/{username}/regenerate-key", response_model=Dict[str, str])
async def regenerate_user_key(
    username: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Regenerate user's API key (admin only)"""
    try:
        # Check if user exists
        user = await database.get_user_by_username(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Generate new unique API key
        new_api_key = generate_api_key()
        
        # Ensure API key is unique
        while await database.get_user_by_key(new_api_key):
            new_api_key = generate_api_key()
        
        # Update user's key
        success = await database.update_user_key(username, new_api_key)
        if success:
            return {"message": "API key regenerated successfully", "new_key": new_api_key}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to regenerate API key"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to regenerate API key: {str(e)}"
        )

@router.post("/staff", response_model=Dict[str, str], status_code=status.HTTP_201_CREATED)
async def create_staff(
    staff_data: StaffCreate,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Create support staff member"""
    try:
        # Sanitize inputs
        staff_data.name = SecurityValidator.sanitize_input(staff_data.name, 100)
        staff_data.username = SecurityValidator.sanitize_input(staff_data.username, 30)
        
        # Check if username or email already exists
        existing_staff = await database.get_staff_by_username(staff_data.username)
        if existing_staff:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        
        # Additional password validation
        is_strong, message = SecurityValidator.is_strong_password(staff_data.password)
        if not is_strong:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        # Hash password
        password_hash = get_password_hash(staff_data.password)
        
        # Prepare staff data
        staff_dict = {
            'name': staff_data.name,
            'username': staff_data.username,
            'email': staff_data.email,
            'password_hash': password_hash,
            'staff_level': staff_data.staff_level
        }
        
        # Create staff
        staff_id = await database.create_staff(staff_dict)
        if staff_id:
            return {
                "message": "Staff member created successfully",
                "staff_id": str(staff_id),
                "username": staff_data.username
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create staff member"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create staff: {str(e)}"
        )

@router.post("/reset-limits", response_model=Dict[str, str])
async def reset_all_user_limits(
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Reset conversation limits for all users"""
    try:
        await database.reset_daily_limits()
        return {"message": "All user limits reset successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset limits: {str(e)}"
        )