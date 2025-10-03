from pydantic import BaseModel, EmailStr, validator
from typing import Optional
from datetime import datetime
import re

class EmailVerificationRequest(BaseModel):
    email: EmailStr

class EmailVerificationVerify(BaseModel):
    email: EmailStr
    otp: str
    
    @validator('otp')
    def validate_otp(cls, v):
        if not re.match(r'^\d{6}$', v):
            raise ValueError('OTP must be exactly 6 digits')
        return v

class EmailVerificationResponse(BaseModel):
    message: str
    success: bool
    attempts_remaining: Optional[int] = None