"""Connector quotas: requests per minute, calendar day and calendar month (UTC).

Counters live in Redis, keyed by connector and period, so they reset at the start
of each period and the current usage can be shown in the interface. A refused
request does not consume quota.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from redis.asyncio import Redis

from app.connectors.base import Quotas


class QuotaExceededError(Exception):
    def __init__(self, window: str) -> None:
        super().__init__(f"quota exceeded: {window}")
        self.window = window


def _windows(now: datetime) -> dict[str, tuple[str, int]]:
    """window -> (period id, key time-to-live in seconds)."""
    return {
        "minute": (now.strftime("%Y%m%d%H%M"), 120),
        "day": (now.strftime("%Y%m%d"), 2 * 86400),
        "month": (now.strftime("%Y%m"), 40 * 86400),
    }


class QuotaGuard:
    def __init__(
        self,
        redis: Redis,
        connector_id: uuid.UUID,
        quotas: Quotas,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._redis = redis
        self._id = connector_id
        self._limits = {
            "minute": quotas.requests_per_minute,
            "day": quotas.requests_per_day,
            "month": quotas.requests_per_month,
        }
        self._clock = clock

    def _key(self, window: str, period: str) -> str:
        return f"quota:{self._id}:{window}:{period}"

    async def consume(self, cost: int = 1) -> None:
        windows = {w: v for w, v in _windows(self._clock()).items() if self._limits[w] is not None}
        if not windows:
            return
        async with self._redis.pipeline(transaction=True) as pipe:
            for window, (period, ttl) in windows.items():
                pipe.incrby(self._key(window, period), cost)
                pipe.expire(self._key(window, period), ttl, nx=True)
            results = await pipe.execute()
        counts = dict(zip(windows, results[::2], strict=True))
        exceeded = next(
            (w for w, count in counts.items() if int(count) > (self._limits[w] or 0)), None
        )
        if exceeded is not None:
            async with self._redis.pipeline(transaction=True) as pipe:
                for window, (period, _) in windows.items():
                    pipe.decrby(self._key(window, period), cost)
                await pipe.execute()
            raise QuotaExceededError(exceeded)

    async def usage(self) -> dict[str, int]:
        windows = _windows(self._clock())
        values = await self._redis.mget([self._key(w, p) for w, (p, _) in windows.items()])
        return {w: int(v or 0) for w, v in zip(windows, values, strict=True)}
