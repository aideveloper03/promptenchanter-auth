from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Literal
from datetime import datetime
import re

class UserCreate(BaseModel):
    username: str
    name: str
    email: EmailStr
    password: str
    confirm_password: str
    about_me: Optional[str] = ""
    hobbies: Optional[str] = ""
    type: Literal["Personal", "Business"] = "Personal"
    
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
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    about_me: Optional[str] = None
    hobbies: Optional[str] = None

class UserResponse(BaseModel):
    username: str
    name: str
    email: str
    about_me: str
    hobbies: str
    type: str
    time_created: datetime
    subscription_plan: str
    credits: Dict[str, int]
    limits: Dict[str, int]
    access_rtype: List[str]
    level: str
    additional_notes: str
    email_verified: bool = False

class UserInDB(BaseModel):
    id: Optional[int] = None
    username: str
    name: str
    email: str
    password_hash: str
    about_me: str
    hobbies: str
    type: str
    time_created: datetime
    subscription_plan: str
    credits: str  # JSON string
    limits: str   # JSON string
    access_rtype: str  # JSON string
    level: str
    additional_notes: str
    key: str
    is_active: bool = True

class KeyResponse(BaseModel):
    key: str
    created_at: datetime

class PasswordReset(BaseModel):
    current_password: str
    new_password: str
    confirm_new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least 1 number')
        return v
    
    @validator('confirm_new_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class EmailUpdate(BaseModel):
    new_email: EmailStr
    password: str