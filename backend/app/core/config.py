from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Union
import json

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cyberwolf SIEM"
    VERSION: str = "1.0.0-hackathon-mvp"
    ENVIRONMENT: str = "development"
    API_V1_STR: str = "/api/v1"
    
    # Deliberately non-secret local-development placeholders. Deployments must
    # override these values through environment configuration.
    SECRET_KEY: str = "development-only-placeholder-change-before-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    DEMO_MODE: bool = True  # Set to False in production to disable demo endpoints
    
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "cyberwolf"
    POSTGRES_PASSWORD: str = "development-only-postgres-password"
    POSTGRES_DB: str = "cyberwolf_db"
    DATABASE_URL: Union[str, None] = None

    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"]

    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_INGEST: str = "500/minute"
    MAX_BATCH_SIZE: int = 100
    MAX_REQUEST_BODY_BYTES: int = 1048576  # 1 MiB payload limit
    SUPPORTED_SOURCE_TYPES: List[str] = ["linux_auth", "json"]
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 100

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def require_non_placeholder_production_credentials(self):
        """Prevent accidental production startup with committed dev placeholders."""
        if self.ENVIRONMENT.lower() == "production":
            placeholders = ("development-only-placeholder", "development-only-postgres-password")
            if (
                not self.SECRET_KEY.strip()
                or not self.POSTGRES_PASSWORD.strip()
                or self.SECRET_KEY.startswith(placeholders)
                or self.POSTGRES_PASSWORD.startswith(placeholders)
            ):
                raise ValueError("Production SECRET_KEY and POSTGRES_PASSWORD must be supplied through environment configuration")
        return self

    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

settings = Settings()
