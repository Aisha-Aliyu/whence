"""Per-user rate limits, counted in fixed windows in memory.

The free host runs one API instance, so memory is enough. With more instances
the counts would move to Postgres or Redis so every instance sees them. Per-IP
limits live in the web server, the only part that sees visitors' addresses.
"""

import threading
import time
from collections.abc import Callable

from app.errors import ApiError


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window: float,
        what: str,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit, self.window, self.what, self.clock = limit, window, what, clock
        self.counts: dict[str, tuple[float, int]] = {}
        self.lock = threading.Lock()

    def hit(self, key: str) -> None:
        """Counts one request for key, or refuses it with 429."""
        now = self.clock()
        with self.lock:
            start, count = self.counts.get(key, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            if count >= self.limit:
                wait = int(start + self.window - now) + 1
                raise ApiError(
                    429,
                    "rate_limited",
                    f"Too many {self.what}. Try again in {wait} seconds.",
                    headers={"Retry-After": str(wait)},
                )
            self.counts[key] = (start, count + 1)
            if len(self.counts) > 10_000:  # forget finished windows
                self.counts = {
                    k: v for k, v in self.counts.items() if now - v[0] < self.window
                }
