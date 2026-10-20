import time

import pyotp
import pytest

from app.core.config import PasswordHashProfile
from app.core.crypto import AesGcmBox, DecryptionError, keyed_hash
from app.iam.passwords import (
    PasswordPolicyError,
    check_password_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.iam.totp import (
    PERIOD,
    new_enrollment,
    new_recovery_codes,
    normalize_recovery_code,
    verify_totp,
)

FAST: PasswordHashProfile = "fast-insecure-tests-only"


@pytest.mark.parametrize(
    ("password", "code"),
    [
        ("short", "password_too_short"),
        ("x" * 129, "password_too_long"),
        ("contortionist", "password_too_common"),
        ("Password2026!!", "password_too_common"),
        ("aaaaaaaaaaaaaaab", "password_too_common"),
        ("alice.martin-Rocks-42", "password_contains_email"),
    ],
)
def test_password_policy_rejections(password: str, code: str) -> None:
    with pytest.raises(PasswordPolicyError, match=code):
        check_password_policy(password, email="alice.martin@example.org")


def test_password_policy_accepts_long_passphrase() -> None:
    check_password_policy("correct horse battery staple", email="alice@example.org")


def test_hash_and_verify() -> None:
    stored = hash_password("correct horse battery staple", FAST)
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse battery staple", FAST)
    assert not verify_password(stored, "wrong horse battery staple", FAST)
    assert not verify_password(None, "anything at all", FAST)  # unknown account
    assert not verify_password("garbage", "anything at all", FAST)
    assert needs_rehash(stored, "strong")


def test_aes_gcm_binds_associated_data() -> None:
    box = AesGcmBox(b"k" * 32)
    blob = box.encrypt(b"totp-secret", b"user-1")
    assert box.decrypt(blob, b"user-1") == b"totp-secret"
    with pytest.raises(DecryptionError):
        box.decrypt(blob, b"user-2")  # secret moved to another user
    with pytest.raises(DecryptionError):
        AesGcmBox(b"z" * 32).decrypt(blob, b"user-1")
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(DecryptionError):
        box.decrypt(tampered, b"user-1")


def test_keyed_hash_is_domain_separated() -> None:
    assert keyed_hash(b"k" * 32, "abc", "invitation") != keyed_hash(b"k" * 32, "abc", "reset")


def test_totp_accepts_current_code_and_refuses_replay() -> None:
    enrollment = new_enrollment("alice@example.org")
    assert enrollment.otpauth_uri.startswith("otpauth://totp/Vuln-Veille:")
    assert enrollment.qr_data_uri.startswith("data:image/png;base64,")
    code = pyotp.TOTP(enrollment.secret).now()
    step = verify_totp(enrollment.secret, code, last_used_step=None)
    assert step == int(time.time()) // PERIOD or step is not None
    assert verify_totp(enrollment.secret, code, last_used_step=step) is None
    assert verify_totp(enrollment.secret, "12345", None) is None
    assert verify_totp(enrollment.secret, "abcdef", None) is None


def test_recovery_codes() -> None:
    codes = new_recovery_codes()
    assert len(codes) == len(set(codes)) == 10
    assert normalize_recovery_code(codes[0].upper().replace("-", " ")) == codes[0]
    assert normalize_recovery_code("too-short") == ""
