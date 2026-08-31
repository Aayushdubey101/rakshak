"""E2E-test isolation. `tests/e2e/test_investigation_api.py` exercises the
real `TestClient(main.app)` without entering it as a context manager (phase 0:
lifespan never runs, since the startup event used to open a browser), so
`create_all()` never happens on its own -- auth (phase 14) is the first thing
in this directory to actually touch the database. Same fixture as
`tests/integration/conftest.py`, needed here for the same reason.
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
