from pydantic import BaseModel
from typing import Dict, List, Any, Optional
from datetime import datetime

class MessageLog(BaseModel):
    username: str
    email: str
    model: str
    messages: List[Dict[str, Any]]
    research_model: bool
    time: datetime

class MessageLogCreate(BaseModel):
    username: str
    email: str
    model: str
    messages: List[Dict[str, Any]]
    research_model: bool = False

class MessageLogInDB(BaseModel):
    id: Optional[int] = None
    username: str
    email: str
    model: str
    messages: str  # JSON string
    research_model: bool
    time: datetime

class BatchMessageLog(BaseModel):
    logs: List[MessageLogCreate]