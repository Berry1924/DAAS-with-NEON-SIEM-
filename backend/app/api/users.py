import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from backend.app.core.security import get_password_hash, validate_password_strength
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole, AuditResult
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.user import UserRead
from backend.app.api.deps import RequireRole

router = APIRouter(prefix="/users", tags=["User Administration"])
require_admin = RequireRole([UserRole.ADMIN])

class UserAdminCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    display_name: str
    role: UserRole = UserRole.ANALYST

class UserAdminUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    request: Request,
    user_in: UserAdminCreate,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Any:
    """Create a new system user (ADMIN only)."""
    request_id = getattr(request.state, "request_id", None)
    
    # Check username uniqueness
    if db.query(User).filter(User.username == user_in.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check email uniqueness if provided
    if user_in.email and db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Validate password bounds
    try:
        validate_password_strength(user_in.password)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )
    
    password_hash = get_password_hash(user_in.password)
    
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        display_name=user_in.display_name,
        password_hash=password_hash,
        role=user_in.role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Audit log
    audit = AuditLog(
        actor_id=admin_user.id,
        action="USER_CREATED",
        target_type="user",
        target_id=str(new_user.id),
        result=AuditResult.SUCCESS,
        request_id=request_id,
        audit_metadata={"username": new_user.username, "role": new_user.role.value}
    )
    db.add(audit)
    db.commit()

    return UserRead.model_validate(new_user)

@router.get("", response_model=List[UserRead])
def list_users(
    skip: int = 0,
    limit: int = 50,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Any:
    """List system users (ADMIN only)."""
    limit = min(limit, 100)
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserRead.model_validate(u) for u in users]

@router.get("/{user_id}", response_model=UserRead)
def get_user(
    user_id: uuid.UUID,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Any:
    """Get user details by ID (ADMIN only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return UserRead.model_validate(user)

@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    request: Request,
    user_id: uuid.UUID,
    user_in: UserAdminUpdate,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Any:
    """Update user role, display name, email, or active status (ADMIN only)."""
    request_id = getattr(request.state, "request_id", None)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    changes = []
    
    if user_in.display_name is not None:
        user.display_name = user_in.display_name
        changes.append("display_name")
        
    if user_in.email is not None and user_in.email != user.email:
        if db.query(User).filter(User.email == user_in.email, User.id != user_id).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        user.email = user_in.email
        changes.append("email")
        
    if user_in.role is not None and user_in.role != user.role:
        old_role = user.role.value
        user.role = user_in.role
        audit_role = AuditLog(
            actor_id=admin_user.id,
            action="USER_ROLE_CHANGED",
            target_type="user",
            target_id=str(user.id),
            result=AuditResult.SUCCESS,
            request_id=request_id,
            audit_metadata={"old_role": old_role, "new_role": user.role.value}
        )
        db.add(audit_role)
        changes.append("role")
        
    if user_in.is_active is not None and user_in.is_active != user.is_active:
        user.is_active = user_in.is_active
        action_name = "USER_ACTIVATED" if user_in.is_active else "USER_DEACTIVATED"
        audit_act = AuditLog(
            actor_id=admin_user.id,
            action=action_name,
            target_type="user",
            target_id=str(user.id),
            result=AuditResult.SUCCESS,
            request_id=request_id,
            audit_metadata={"is_active": user.is_active}
        )
        db.add(audit_act)
        changes.append("is_active")

    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    return UserRead.model_validate(user)
