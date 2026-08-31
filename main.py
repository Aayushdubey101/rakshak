"""Entrypoint shim. The application lives in `apps/api/main.py`."""

from apps.api.main import app, run  # noqa: F401  (`uvicorn main:app` imports `app`)

if __name__ == "__main__":
    run()
