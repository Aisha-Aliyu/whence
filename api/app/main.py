"""The Whence API. Run it with: uv run uvicorn app.main:create_app --factory"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import documents, errors, workspaces
from app.auth import TokenVerifier
from app.db import open_pool
from app.embeddings import CloudflareEmbedder, Embedder
from app.settings import Settings


def create_app(
    settings: Settings | None = None,
    verifier: TokenVerifier | None = None,
    embedder: Embedder | None = None,
) -> FastAPI:
    config = settings or Settings()  # values come from the environment
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    # httpx logs every request URL, and Cloudflare's include our account ID.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cloudflare = None
        if embedder is None:  # fails at start when the Cloudflare settings are missing
            cloudflare = CloudflareEmbedder(
                config.cloudflare_account_id,
                config.cloudflare_api_token.get_secret_value(),
            )
        app.state.embedder = embedder or cloudflare
        app.state.settings = config
        app.state.pool = open_pool(
            config.database_url.get_secret_value(),
            config.db_pool_size,
            config.db_timeout_seconds,
        )
        app.state.verifier = verifier or TokenVerifier(
            config.jwks_url, config.jwt_issuer, config.jwt_audience
        )
        yield
        if cloudflare:
            cloudflare.close()
        app.state.pool.close()

    app = FastAPI(title="Whence API", version="0.1.0", lifespan=lifespan)
    errors.install(app)
    app.include_router(workspaces.router)
    app.include_router(documents.router)

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
