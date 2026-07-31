import pytest

from backend.app.core.config import Settings


def test_production_rejects_committed_development_placeholders():
    with pytest.raises(ValueError, match="Production SECRET_KEY"):
        Settings(ENVIRONMENT="production")


def test_production_accepts_environment_supplied_non_placeholder_credentials():
    settings = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="test-only-production-key-with-sufficient-length",
        POSTGRES_PASSWORD="test-only-production-password",
    )
    assert settings.ENVIRONMENT == "production"
