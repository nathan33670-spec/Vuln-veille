"""TOTP (RFC 6238) with replay protection, and single-use recovery codes."""

import secrets
import time
from dataclasses import dataclass

import pyotp
import segno

ISSUER = "Vuln-Veille"
DIGITS = 6
PERIOD = 30
# Accept the previous and next step to absorb clock drift.
VALID_WINDOW = 1
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no ambiguous characters


@dataclass(frozen=True)
class Enrollment:
    secret: str
    otpauth_uri: str
    qr_data_uri: str


def new_enrollment(account_name: str) -> Enrollment:
    secret = pyotp.random_base32(length=32)
    uri = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD).provisioning_uri(
        name=account_name, issuer_name=ISSUER
    )
    qr = segno.make(uri, error="m").png_data_uri(scale=5, border=2)
    return Enrollment(secret=secret, otpauth_uri=uri, qr_data_uri=qr)


def verify_totp(secret: str, code: str, last_used_step: int | None) -> int | None:
    """Returns the matched time step, or None. A step already used is refused (replay)."""
    normalized = code.replace(" ", "")
    if len(normalized) != DIGITS or not normalized.isdigit():
        return None
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD)
    current = int(time.time()) // PERIOD
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if secrets.compare_digest(totp.at(step * PERIOD), normalized):
            return step
    return None


def new_recovery_codes() -> list[str]:
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        return f"{raw[:5]}-{raw[5:]}"

    return [one() for _ in range(RECOVERY_CODE_COUNT)]


def normalize_recovery_code(code: str) -> str:
    raw = "".join(ch for ch in code.lower() if ch.isalnum())
    return f"{raw[:5]}-{raw[5:]}" if len(raw) == 10 else ""  # noqa: PLR2004
