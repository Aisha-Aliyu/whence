"""Checks the Supabase access token on every request that needs a signed-in user.

Supabase signs access tokens with asymmetric keys and publishes the public keys
as a JSON Web Key Set. The API accepts only those algorithms, checks the
audience, issuer and expiry, and trusts nothing else in the token.
"""

from typing import Annotated, Any
from uuid import UUID

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.errors import ApiError

ALGORITHMS = ["ES256", "RS256"]
REQUIRED_CLAIMS = ["exp", "iat", "sub", "aud", "iss"]


class TokenVerifier:
    def __init__(self, jwks_url: str, issuer: str, audience: str) -> None:
        self.jwks = jwt.PyJWKClient(
            jwks_url, cache_jwk_set=True, lifespan=600, timeout=5
        )
        self.issuer = issuer
        self.audience = audience

    def signing_key(self, token: str) -> Any:
        return self.jwks.get_signing_key_from_jwt(token).key

    def user_id(self, token: str) -> UUID:
        """The signed-in user's ID, or a 401 error for any token that fails a check."""
        try:
            claims = jwt.decode(
                token,
                self.signing_key(token),
                algorithms=ALGORITHMS,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": REQUIRED_CLAIMS},
                leeway=30,  # seconds of clock skew between Supabase and us
            )
            return UUID(str(claims["sub"]))
        except jwt.PyJWKClientConnectionError as error:
            raise ApiError(
                503, "auth_unavailable", "Sign-in is unavailable. Try again."
            ) from error
        except (jwt.PyJWTError, ValueError) as error:
            raise ApiError(
                401, "invalid_token", "Your session is not valid. Sign in again."
            ) from error


bearer = HTTPBearer(auto_error=False)


def current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> UUID:
    if credentials is None:
        raise ApiError(401, "missing_token", "Sign in to continue.")
    verifier: TokenVerifier = request.app.state.verifier
    return verifier.user_id(credentials.credentials)


CurrentUser = Annotated[UUID, Depends(current_user)]
