"""Login helpers for integration tests."""

from tests.integration.conftest import Api
from tests.integration.seed import SeededUser


async def sign_in(api: Api, user: SeededUser) -> str:
    """Logs in (with the second factor when enrolled) and returns the CSRF token."""
    response = await api.client.post(
        api.url("/auth/login"), json={"email": user.email, "password": user.password}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    if body["status"] == "mfa_required":
        verified = await api.client.post(
            api.url("/auth/mfa/verify"),
            json={"code": user.totp_now()},
            headers={"x-csrf-token": body["csrf_token"]},
        )
        assert verified.status_code == 200, verified.text
        return str(verified.json()["csrf_token"])
    assert body["status"] == "authenticated", body
    return str(body["csrf_token"])
