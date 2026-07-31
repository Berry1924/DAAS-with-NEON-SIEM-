import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr
from backend.app.models.enums import UserRole

class UserBase(BaseModel):
    username: str
    email: str | None = None
    display_name: str
    role: UserRole = UserRole.ANALYST
    is_active: bool = True

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: uuid.UUID
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
