"""Security-test isolation. Same fixture as `tests/integration/conftest.py` and
`tests/e2e/conftest.py` -- `test_auth.py` exercises the real `TestClient(main.app)`
without lifespan, so `create_all()` never runs on its own.
"""

import pytest

from packages.shared.db.engine import create_all, dispose_engine, reset_engine_cache
from packages.shared.db.repositories import reset_repository_cache


@pytest.fixture(autouse=True)
async def isolated_database():
    reset_engine_cache()
    reset_repository_cache()
    await create_all()
    yield
    await dispose_engine()
    reset_repository_cache()
