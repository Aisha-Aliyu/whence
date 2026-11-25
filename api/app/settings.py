"""Settings come from environment variables, and from api/.env in local development."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: SecretStr  # postgresql://user:password@host:5432/database
    supabase_url: str  # https://<project>.supabase.co
    jwt_audience: str = "authenticated"
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    # Cloudflare Workers AI makes the embeddings. Required unless a test
    # passes its own embedder.
    cloudflare_account_id: str = ""
    cloudflare_api_token: SecretStr = SecretStr("")
    max_upload_bytes: int = Field(default=10_000_000, ge=1, le=50_000_000)
    workspace_bytes: int = Field(default=50_000_000, ge=1)  # per workspace
    # Per user. Each question costs about 130 of the 10,000 free Neurons a day.
    questions_per_hour: int = Field(default=30, ge=1)
    uploads_per_hour: int = Field(default=20, ge=1)

    @property
    def jwt_issuer(self) -> str:
        return f"{self.supabase_url.rstrip('/')}/auth/v1"

    @property
    def jwks_url(self) -> str:
        return f"{self.jwt_issuer}/.well-known/jwks.json"
