"""Password hashing (Argon2id) and password policy (NIST SP 800-63B, ANSSI)."""

import contextlib
from functools import lru_cache
from importlib import resources

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import PasswordHashProfile

MIN_LENGTH = 12
# Upper bound keeps Argon2 cost predictable (no DoS through megabyte passwords).
MAX_LENGTH = 128


@lru_cache(maxsize=2)
def _hasher(profile: PasswordHashProfile) -> PasswordHasher:
    if profile == "strong":
        # 64 MiB, 3 passes, 4 lanes (SECURITY.md §4.1); recalibrate on the target server.
        return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    return PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    text = resources.files("app.iam.data").joinpath("common-passwords.txt").read_text("utf-8")
    return frozenset(line for line in text.splitlines() if line)


class PasswordPolicyError(ValueError):
    """The message is a stable code, translated by the front end."""


def check_password_policy(password: str, email: str | None = None) -> None:
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError("password_too_short")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError("password_too_long")
    lowered = password.lower()
    # Also catches the usual "common word + digits/symbols" pattern (Password2026!).
    stem = lowered.rstrip("0123456789!?.@#$%&*_-+= ")
    common = _common_passwords()
    if lowered in common or stem in common or len(set(password)) < 4:  # noqa: PLR2004
        raise PasswordPolicyError("password_too_common")
    if email:
        local_part = email.split("@", 1)[0].lower()
        if len(local_part) >= 4 and local_part in lowered:  # noqa: PLR2004
            raise PasswordPolicyError("password_contains_email")


def hash_password(password: str, profile: PasswordHashProfile) -> str:
    return _hasher(profile).hash(password)


def verify_password(stored_hash: str | None, password: str, profile: PasswordHashProfile) -> bool:
    """Constant-work verification: an unknown account still costs one Argon2 run."""
    hasher = _hasher(profile)
    if stored_hash is None:
        with contextlib.suppress(VerifyMismatchError):
            hasher.verify(_dummy_hash(profile), "x" * MIN_LENGTH + "!")
        return False
    try:
        return hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str, profile: PasswordHashProfile) -> bool:
    return _hasher(profile).check_needs_rehash(stored_hash)


@lru_cache(maxsize=2)
def _dummy_hash(profile: PasswordHashProfile) -> str:
    return _hasher(profile).hash("not-a-real-password-for-timing")
