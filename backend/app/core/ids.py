"""UUIDv7 identifiers (RFC 9562): time-ordered for index locality, random otherwise."""

import secrets
import time
import uuid


def uuid7() -> uuid.UUID:
    unix_ms = time.time_ns() // 1_000_000
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    value = (unix_ms & 0xFFFF_FFFF_FFFF) << 80
    value |= 0x7 << 76  # version
    value |= rand_a << 64
    value |= 0b10 << 62  # RFC 9562 variant
    value |= rand_b
    return uuid.UUID(int=value)
