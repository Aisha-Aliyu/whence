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

    @property
    def jwt_issuer(self) -> str:
        return f"{self.supabase_url.rstrip('/')}/auth/v1"

    @property
    def jwks_url(self) -> str:
        return f"{self.jwt_issuer}/.well-known/jwks.json"
