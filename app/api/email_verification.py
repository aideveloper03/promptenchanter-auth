"""
Email Verification API endpoints
"""

from fastapi import APIRouter, HTTPException, status, Depends, Request
from datetime import datetime, timedelta
from typing import Dict, Any

from ..models.email_verification import (
    EmailVerificationRequest, 
    EmailVerificationVerify, 
    EmailVerificationResponse
)
from ..db.mongodb_database import mongodb_database as database
from ..services.email_service import email_service
from ..core.config import settings
from .dependencies import get_current_user

router = APIRouter(prefix="/email", tags=["Email Verification"])

@router.post("/send-verification", response_model=EmailVerificationResponse)
async def send_verification_email(
    request_data: EmailVerificationRequest,
    request: Request
):
    """Send email verification OTP"""
    try:
        # Check if email verification is enabled
        if not settings.ENABLE_EMAIL_VERIFICATION:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email verification is not enabled"
            )
        
        # Check if user exists
        user = await database.get_user_by_email(request_data.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check if already verified
        if user.get('email_verified', False):
            return EmailVerificationResponse(
                message="Email is already verified",
                success=True
            )
        
        # Check daily attempt limit
        attempts_today = await database.get_verification_attempts_today(request_data.email)
        if attempts_today >= settings.MAX_VERIFICATION_ATTEMPTS_PER_DAY:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Maximum {settings.MAX_VERIFICATION_ATTEMPTS_PER_DAY} verification attempts per day exceeded"
            )
        
        # Generate OTP
        otp = email_service.generate_otp()
        
        # Set expiration time
        expires_at = datetime.utcnow() + timedelta(minutes=settings.EMAIL_VERIFICATION_EXPIRE_MINUTES)
        
        # Save verification record
        verification_id = await database.create_email_verification(
            request_data.email, 
            otp, 
            expires_at
        )
        
        if not verification_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create verification record"
            )
        
        # Send email
        email_sent = await email_service.send_verification_email(
            request_data.email, 
            otp, 
            user['username']
        )
        
        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email"
            )
        
        attempts_remaining = settings.MAX_VERIFICATION_ATTEMPTS_PER_DAY - attempts_today - 1
        
        return EmailVerificationResponse(
            message="Verification email sent successfully",
            success=True,
            attempts_remaining=attempts_remaining
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send verification email: {str(e)}"
        )

@router.post("/verify", response_model=EmailVerificationResponse)
async def verify_email(
    verify_data: EmailVerificationVerify,
    request: Request
):
    """Verify email with OTP"""
    try:
        # Check if email verification is enabled
        if not settings.ENABLE_EMAIL_VERIFICATION:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email verification is not enabled"
            )
        
        # Check if user exists
        user = await database.get_user_by_email(verify_data.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check if already verified
        if user.get('email_verified', False):
            return EmailVerificationResponse(
                message="Email is already verified",
                success=True
            )
        
        # Get verification record
        verification = await database.get_email_verification(verify_data.email, verify_data.otp)
        if not verification:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        # Mark verification as used
        await database.mark_verification_used(verification['id'])
        
        # Update user email verification status
        success = await database.update_email_verification_status(user['username'], True)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update verification status"
            )
        
        return EmailVerificationResponse(
            message="Email verified successfully",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify email: {str(e)}"
        )

@router.post("/resend-verification", response_model=EmailVerificationResponse)
async def resend_verification_email(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Resend verification email for current user"""
    try:
        # Check if email verification is enabled
        if not settings.ENABLE_EMAIL_VERIFICATION:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email verification is not enabled"
            )
        
        # Check if already verified
        if current_user.get('email_verified', False):
            return EmailVerificationResponse(
                message="Email is already verified",
                success=True
            )
        
        # Check daily attempt limit
        attempts_today = await database.get_verification_attempts_today(current_user['email'])
        if attempts_today >= settings.MAX_VERIFICATION_ATTEMPTS_PER_DAY:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Maximum {settings.MAX_VERIFICATION_ATTEMPTS_PER_DAY} verification attempts per day exceeded"
            )
        
        # Generate OTP
        otp = email_service.generate_otp()
        
        # Set expiration time
        expires_at = datetime.utcnow() + timedelta(minutes=settings.EMAIL_VERIFICATION_EXPIRE_MINUTES)
        
        # Save verification record
        verification_id = await database.create_email_verification(
            current_user['email'], 
            otp, 
            expires_at
        )
        
        if not verification_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create verification record"
            )
        
        # Send email
        email_sent = await email_service.send_verification_email(
            current_user['email'], 
            otp, 
            current_user['username']
        )
        
        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email"
            )
        
        attempts_remaining = settings.MAX_VERIFICATION_ATTEMPTS_PER_DAY - attempts_today - 1
        
        return EmailVerificationResponse(
            message="Verification email sent successfully",
            success=True,
            attempts_remaining=attempts_remaining
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to resend verification email: {str(e)}"
        )