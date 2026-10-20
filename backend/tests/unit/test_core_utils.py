import json

from app.core.ids import uuid7
from app.core.logging import REDACTED, redact_secrets
from tests.conftest import make_settings


def test_uuid7_version_variant_and_order() -> None:
    ids = [uuid7() for _ in range(200)]
    assert all(u.version == 7 for u in ids)
    assert all(u.variant == "specified in RFC 4122" for u in ids)
    timestamps = [u.int >> 80 for u in ids]
    assert timestamps == sorted(timestamps)
    assert len(set(ids)) == len(ids)


def test_log_redaction_masks_keys_and_url_credentials() -> None:
    event = redact_secrets(
        None,
        "info",
        {
            "event": "connect",
            "password": "hunter2",
            "headers": {"Authorization": "Bearer abc", "accept": "json"},
            "dsn_hint": "postgresql://vv_app:s3cr3t@db:5432/vv",
            "target": "postgresql://vv_app:s3cr3t@db:5432/vv",
        },
    )
    serialized = json.dumps(event)
    assert "hunter2" not in serialized
    assert "s3cr3t" not in serialized
    assert "Bearer abc" not in serialized
    assert event["password"] == REDACTED
    assert event["headers"]["accept"] == "json"


def test_settings_repr_hides_secrets() -> None:
    settings = make_settings()
    assert "unused:unused" not in repr(settings)
    assert "unused:unused" not in str(settings.model_dump())
