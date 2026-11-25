"""Calls to Cloudflare Workers AI, with a timeout and retries.

The free plan includes 10,000 Neurons a day, and calls fail with an error past
that until 00:00 UTC. Cloudflare does not train on what we send, and for
standard inference it keeps nothing after the request, apart from the
exceptions its policy lists:
https://developers.cloudflare.com/workers-ai/platform/privacy/
"""

import logging
import random
import time
from collections.abc import Callable

import httpx

log = logging.getLogger(__name__)

RETRY_STATUSES = {408, 429, 500, 502, 503, 504}


class WorkersAIError(Exception):
    """Workers AI could not answer."""


class WorkersAI:
    def __init__(
        self,
        account_id: str,
        api_token: str,
        *,
        timeout: float = 15.0,
        attempts: int = 4,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not account_id or not api_token:
            raise ValueError("Set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN.")
        self.attempts = max(1, attempts)
        self.sleep = sleep
        url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/"
        self.client = httpx.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()

    def run(
        self, model: str, body: dict[str, object], stream: bool = False
    ) -> httpx.Response:
        """Retries timeouts, rate limits and server errors with backoff and jitter.

        A streamed response is retried only before it starts, so no text is sent
        twice. The caller closes a streamed response.
        """
        attempt = 1
        while True:
            try:
                request = self.client.build_request("POST", model, json=body)
                response = self.client.send(request, stream=stream)
                if response.status_code not in RETRY_STATUSES:
                    return response
                response.close()
                problem = f"HTTP {response.status_code}"
            except httpx.TransportError as error:  # includes timeouts
                problem = type(error).__name__
            if attempt == self.attempts:
                raise WorkersAIError(f"Gave up after {attempt} attempts: {problem}")
            # Exponential backoff with full jitter. Not security, so random is fine.
            delay = random.uniform(0, 0.5 * 2**attempt)  # noqa: S311
            log.warning("Workers AI failed (%s), retrying in %.1fs", problem, delay)
            self.sleep(delay)
            attempt += 1
