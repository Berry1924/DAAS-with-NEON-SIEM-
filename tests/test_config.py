import pytest

from backend.app.core.config import Settings


def test_production_rejects_committed_development_placeholders():
    with pytest.raises(ValueError, match="Production SECRET_KEY"):
        Settings(ENVIRONMENT="production")


@pytest.mark.parametrize(
    ("secret_key", "postgres_password"),
    [
        ("", "test-only-production-password"),
        ("test-only-production-key", ""),
        ("   ", "test-only-production-password"),
        ("test-only-production-key", "   "),
    ],
)
def test_production_rejects_blank_credentials(secret_key, postgres_password):
    with pytest.raises(ValueError, match="Production SECRET_KEY"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=secret_key,
            POSTGRES_PASSWORD=postgres_password,
        )


def test_production_accepts_environment_supplied_non_placeholder_credentials():
    settings = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="test-only-production-key-with-sufficient-length",
        POSTGRES_PASSWORD="test-only-production-password",
    )
    assert settings.ENVIRONMENT == "production"
