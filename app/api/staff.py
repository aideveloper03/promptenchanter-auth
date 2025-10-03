from fastapi import APIRouter, HTTPException, status, Depends, Request, Query
from datetime import timedelta
import json
from typing import Dict, Any, List

from ..models.admin import StaffLogin, StaffUserUpdate
from ..models.user import UserResponse
from ..db.mongodb_database import mongodb_database as database
from ..security.auth import verify_password, create_access_token, SecurityValidator
from ..core.config import settings
from .dependencies import get_current_staff

router = APIRouter(prefix="/staff", tags=["Support Staff"])

@router.post("/login", response_model=Dict[str, str])
async def staff_login(staff_login: StaffLogin, request: Request):
    """Staff login"""
    try:
        # Validate IP if whitelisting is enabled
        from ..security.auth import validate_ip_address
        client_ip = request.client.host
        if not validate_ip_address(client_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address not whitelisted"
            )
        
        # Get staff
        staff = await database.get_staff_by_username(staff_login.username)
        if not staff or not verify_password(staff_login.password, staff['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": staff['username'], 
                "role": "staff",
                "staff_level": staff['staff_level']
            },
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": str(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60),
            "staff_level": staff['staff_level']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Staff login failed: {str(e)}"
        )

@router.get("/users", response_model=List[UserResponse])
async def get_users_for_staff(
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    current_staff: Dict[str, Any] = Depends(get_current_staff)
):
    """Get users for staff (read-only access to user information)"""
    try:
        users_data = await database.get_all_users(limit, offset)
        users = []
        
        for user_data in users_data:
            # Hide password hash and sensitive info for 'new' level staff
            if current_staff['staff_level'] == 'new':
                user = UserResponse(
                    username=user_data['username'],
                    name=user_data['name'],
                    email=user_data['email'],
                    about_me=user_data['about_me'],
                    hobbies=user_data['hobbies'],
                    type=user_data['type'],
                    time_created=user_data['time_created'],
                    subscription_plan=user_data['subscription_plan'],
                    credits=user_data['credits'] if isinstance(user_data['credits'], dict) else json.loads(user_data['credits']),
                    limits=user_data['limits'] if isinstance(user_data['limits'], dict) else json.loads(user_data['limits']),
                    access_rtype=user_data['access_rtype'] if isinstance(user_data['access_rtype'], list) else json.loads(user_data['access_rtype']),
                    level=user_data['level'],
                    additional_notes=""  # Hide additional notes for new staff
                )
            else:
                user = UserResponse(
                    username=user_data['username'],
                    name=user_data['name'],
                    email=user_data['email'],
                    about_me=user_data['about_me'],
                    hobbies=user_data['hobbies'],
                    type=user_data['type'],
                    time_created=user_data['time_created'],
                    subscription_plan=user_data['subscription_plan'],
                    credits=user_data['credits'] if isinstance(user_data['credits'], dict) else json.loads(user_data['credits']),
                    limits=user_data['limits'] if isinstance(user_data['limits'], dict) else json.loads(user_data['limits']),
                    access_rtype=user_data['access_rtype'] if isinstance(user_data['access_rtype'], list) else json.loads(user_data['access_rtype']),
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
async def get_user_for_staff(
    username: str,
    current_staff: Dict[str, Any] = Depends(get_current_staff)
):
    """Get specific user by username (staff access)"""
    try:
        user_data = await database.get_user_by_username(username)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Hide sensitive info for 'new' level staff
        if current_staff['staff_level'] == 'new':
            return UserResponse(
                username=user_data['username'],
                name=user_data['name'],
                email=user_data['email'],
                about_me=user_data['about_me'],
                hobbies=user_data['hobbies'],
                type=user_data['type'],
                time_created=user_data['time_created'],
                subscription_plan=user_data['subscription_plan'],
                credits=user_data['credits'] if isinstance(user_data['credits'], dict) else json.loads(user_data['credits']),
                limits=user_data['limits'] if isinstance(user_data['limits'], dict) else json.loads(user_data['limits']),
                access_rtype=user_data['access_rtype'] if isinstance(user_data['access_rtype'], list) else json.loads(user_data['access_rtype']),
                level=user_data['level'],
                additional_notes=""  # Hide additional notes for new staff
            )
        else:
            return UserResponse(
                username=user_data['username'],
                name=user_data['name'],
                email=user_data['email'],
                about_me=user_data['about_me'],
                hobbies=user_data['hobbies'],
                type=user_data['type'],
                time_created=user_data['time_created'],
                subscription_plan=user_data['subscription_plan'],
                credits=user_data['credits'] if isinstance(user_data['credits'], dict) else json.loads(user_data['credits']),
                limits=user_data['limits'] if isinstance(user_data['limits'], dict) else json.loads(user_data['limits']),
                access_rtype=user_data['access_rtype'] if isinstance(user_data['access_rtype'], list) else json.loads(user_data['access_rtype']),
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
async def update_user_for_staff(
    username: str,
    update_data: StaffUserUpdate,
    current_staff: Dict[str, Any] = Depends(get_current_staff)
):
    """Update user information (staff permissions based on level)"""
    try:
        # Check staff permissions
        staff_level = current_staff['staff_level']
        
        if staff_level == 'new':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions. New staff can only read user information."
            )
        
        # Check if user exists
        user = await database.get_user_by_username(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prepare update data based on staff level
        update_dict = {}
        
        if staff_level in ['support', 'advanced']:
            if update_data.email is not None:
                # Check if email is already taken by another user
                existing_user = await database.get_user_by_email(update_data.email)
                if existing_user and existing_user['username'] != username:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already taken by another user"
                    )
                update_dict['email'] = update_data.email
            
            if update_data.limits is not None:
                update_dict['limits'] = json.dumps(update_data.limits)
            
            if update_data.subscription_plan is not None:
                update_dict['subscription_plan'] = update_data.subscription_plan
        
        # Advanced staff can update more fields
        if staff_level == 'advanced':
            # Advanced staff gets same permissions as support for now
            # You can add more fields here if needed
            pass
        
        if not update_dict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid fields to update or insufficient permissions"
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
async def delete_user_for_staff(
    username: str,
    current_staff: Dict[str, Any] = Depends(get_current_staff)
):
    """Delete user account (only advanced staff)"""
    try:
        # Check staff permissions
        if current_staff['staff_level'] != 'advanced':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only advanced staff can delete user accounts"
            )
        
        success = await database.delete_user(username, f"staff:{current_staff['username']}")
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

@router.get("/profile", response_model=Dict[str, Any])
async def get_staff_profile(current_staff: Dict[str, Any] = Depends(get_current_staff)):
    """Get current staff profile"""
    try:
        return {
            "id": current_staff['id'],
            "name": current_staff['name'],
            "username": current_staff['username'],
            "email": current_staff['email'],
            "staff_level": current_staff['staff_level'],
            "time_created": current_staff['time_created'],
            "is_active": current_staff['is_active']
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get staff profile: {str(e)}"
        )