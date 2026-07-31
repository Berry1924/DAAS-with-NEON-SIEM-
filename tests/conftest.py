import pytest

from backend.app.core.rate_limit import limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Keep in-memory SlowAPI counters isolated between test cases."""
    limiter.reset()
    yield
    limiter.reset()
