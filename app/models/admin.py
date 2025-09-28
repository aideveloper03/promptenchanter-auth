from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Literal
from datetime import datetime
import re

class AdminLogin(BaseModel):
    username: str
    password: str

class AdminUserUpdate(BaseModel):
    username: Optional[str] = None
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    about_me: Optional[str] = None
    hobbies: Optional[str] = None
    type: Optional[Literal["Personal", "Business"]] = None
    subscription_plan: Optional[str] = None
    credits: Optional[Dict[str, int]] = None
    limits: Optional[Dict[str, int]] = None
    access_rtype: Optional[List[str]] = None
    level: Optional[str] = None
    additional_notes: Optional[str] = None
    is_active: Optional[bool] = None

class StaffCreate(BaseModel):
    name: str
    username: str
    email: EmailStr
    password: str
    staff_level: Literal["new", "support", "advanced"]
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3 or len(v) > 30:
            raise ValueError('Username must be between 3 and 30 characters')
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least 1 number')
        return v

class StaffLogin(BaseModel):
    username: str
    password: str

class StaffInDB(BaseModel):
    id: Optional[int] = None
    name: str
    username: str
    email: str
    password_hash: str
    staff_level: str
    time_created: datetime
    is_active: bool = True

class StaffResponse(BaseModel):
    id: int
    name: str
    username: str
    email: str
    staff_level: str
    time_created: datetime
    is_active: bool

class StaffUserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    limits: Optional[Dict[str, int]] = None
    subscription_plan: Optional[str] = None