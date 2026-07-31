from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Union
import json

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cyberwolf SIEM"
    VERSION: str = "1.0.0-hackathon-mvp"
    ENVIRONMENT: str = "development"
    API_V1_STR: str = "/api/v1"
    
    SECRET_KEY: str = "cyberwolf_default_dev_secret_key_never_use_in_prod_32b"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "cyberwolf"
    POSTGRES_PASSWORD: str = "cyberwolf_dev_password"
    POSTGRES_DB: str = "cyberwolf_db"
    DATABASE_URL: Union[str, None] = None

    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"]

    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_INGEST: str = "500/minute"
    MAX_BATCH_SIZE: int = 100
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 100

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

settings = Settings()
