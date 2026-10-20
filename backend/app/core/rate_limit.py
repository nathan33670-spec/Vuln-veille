"""Fixed-window rate limiting backed by Redis."""

import hashlib

from redis.asyncio import Redis


class RateLimiter:
    def __init__(self, redis: Redis, prefix: str = "rl") -> None:
        self._redis = redis
        self._prefix = prefix

    async def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> bool:
        """Counts one attempt; returns False when the limit is exceeded."""
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]  # no raw e-mail/IP in Redis keys
        redis_key = f"{self._prefix}:{bucket}:{digest}"
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incr(redis_key)
            pipe.expire(redis_key, window_seconds, nx=True)
            count, _ = await pipe.execute()
        return int(count) <= limit
