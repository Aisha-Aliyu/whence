"""The Whence API. Run it with: uv run uvicorn app.main:create_app --factory"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import ask, documents, errors, workspaces
from app.auth import TokenVerifier
from app.db import open_pool
from app.embeddings import CloudflareEmbedder, Embedder
from app.llm import ChatModel, CloudflareChat
from app.ratelimit import RateLimiter
from app.settings import Settings


def create_app(
    settings: Settings | None = None,
    verifier: TokenVerifier | None = None,
    embedder: Embedder | None = None,
    chat: ChatModel | None = None,
) -> FastAPI:
    """Tests pass their own verifier and models. In production the models come
    from Cloudflare, and the API refuses to start without its settings."""
    config = settings or Settings()  # values come from the environment
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    # httpx logs every request URL, and Cloudflare's include our account ID.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        account = config.cloudflare_account_id
        token = config.cloudflare_api_token.get_secret_value()
        own_embedder = None if embedder else CloudflareEmbedder(account, token)
        own_chat = None if chat else CloudflareChat(account, token)
        app.state.embedder = embedder or own_embedder
        app.state.chat = chat or own_chat
        app.state.settings = config
        app.state.question_limiter = RateLimiter(
            config.questions_per_hour, 3600, "questions"
        )
        app.state.upload_limiter = RateLimiter(config.uploads_per_hour, 3600, "uploads")
        app.state.pool = open_pool(
            config.database_url.get_secret_value(),
            config.db_pool_size,
            config.db_timeout_seconds,
        )
        app.state.verifier = verifier or TokenVerifier(
            config.jwks_url, config.jwt_issuer, config.jwt_audience
        )
        yield
        for client in (own_embedder, own_chat):
            if client:
                client.close()
        app.state.pool.close()

    app = FastAPI(title="Whence API", version="0.1.0", lifespan=lifespan)
    errors.install(app)
    app.include_router(workspaces.router)
    app.include_router(documents.router)
    app.include_router(ask.router)

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
