"""The Whence API. Run it with: uv run uvicorn app.main:create_app --factory"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import errors, workspaces
from app.auth import TokenVerifier
from app.db import open_pool
from app.settings import Settings


def create_app(
    settings: Settings | None = None, verifier: TokenVerifier | None = None
) -> FastAPI:
    config = settings or Settings()  # values come from the environment

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.pool = open_pool(
            config.database_url.get_secret_value(),
            config.db_pool_size,
            config.db_timeout_seconds,
        )
        app.state.verifier = verifier or TokenVerifier(
            config.jwks_url, config.jwt_issuer, config.jwt_audience
        )
        yield
        app.state.pool.close()

    app = FastAPI(title="Whence API", version="0.1.0", lifespan=lifespan)
    errors.install(app)
    app.include_router(workspaces.router)

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        """The process is running."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    def readyz(request: Request) -> JSONResponse:
        """The API can reach its database."""
        try:
            with request.app.state.pool.connection(timeout=2) as conn:
                conn.execute("SELECT 1")
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    return app
