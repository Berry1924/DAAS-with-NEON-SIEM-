from datetime import datetime, timezone
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.rate_limit import limiter
from backend.app.core.security import verify_password, create_access_token, validate_password_strength
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import AuditResult
from backend.app.schemas.user import UserRead
from backend.app.api.deps import get_current_active_user
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/auth", tags=["Authentication"])

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login", response_model=TokenResponse)
@limiter.limit(lambda: settings.RATE_LIMIT_LOGIN)
def login(
    request: Request,
    login_data: Optional[LoginRequest] = None,
    db: Session = Depends(get_db)
) -> Any:
    """Authenticate user with username and password, returning JWT access token."""
    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    username = None
    password = None

    if login_data:
        username = login_data.username
        password = login_data.password

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password required"
        )

    # Fetch user
    user = db.query(User).filter(User.username == username).first()

    # Generic authentication error (SEC-04 / SEC-07)
    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user or not verify_password(password, user.password_hash):
        # Audit failed login via AuditService
        audit_service.log(
            db=db,
            action=audit_service.LOGIN_FAILURE,
            actor_id=None,
            target_type="user",
            target_id=username,
            result=AuditResult.FAILURE,
            request_id=request_id,
            source_ip=client_ip,
            metadata={"reason": "Invalid credentials", "username": username}
        )
        raise auth_error

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )

    # Update last login timestamp
    user.last_login_at = datetime.now(timezone.utc)
    
    # Audit successful login via AuditService
    audit_service.log(
        db=db,
        action=audit_service.LOGIN_SUCCESS,
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
        result=AuditResult.SUCCESS,
        request_id=request_id,
        source_ip=client_ip,
        metadata={"username": user.username, "role": user.role.value}
    )
    db.refresh(user)

    # Generate JWT
    access_token = create_access_token(subject=user.username, role=user.role.value)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserRead.model_validate(user)
    }

@router.get("/me", response_model=UserRead)
def read_current_user(
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """Return currently authenticated user details."""
    return current_user

@router.post("/logout")
def logout(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
) -> Any:
    """End session / logout current user (stateless JWT; client discards token)."""
    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    audit_service.log(
        db=db,
        action="USER_LOGOUT",
        actor_id=current_user.id,
        target_type="user",
        target_id=str(current_user.id),
        result=AuditResult.SUCCESS,
        request_id=request_id,
        source_ip=client_ip,
        metadata={"username": current_user.username}
    )
    return {"message": "Successfully logged out. Note: Stateless JWT tokens are discarded client-side and remain valid until expiration."}

