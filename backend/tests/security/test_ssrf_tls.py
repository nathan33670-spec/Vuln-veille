"""Real TLS through IP pinning: SNI and certificate checks use the host name."""

import asyncio
import datetime
import ssl
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.net import safe_http
from app.net.safe_http import EgressError, EgressPolicy, SafeHttpClient


def _self_signed(name: str, directory: Path) -> tuple[str, Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_path, key_path = directory / f"{name}.crt", directory / f"{name}.key"
    cert_path.write_text(pem)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return pem, cert_path, key_path


class Server:
    def __init__(self) -> None:
        self.sni: list[str | None] = []
        self.requests: list[bytes] = []
        self.port = 0


@pytest.fixture
async def tls_server(tmp_path: Path) -> AsyncIterator[tuple[Server, str, str]]:
    good_pem, cert, key = _self_signed("pinned.test", tmp_path)
    other_pem, _, _ = _self_signed("other.test", tmp_path)
    server = Server()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)
    context.sni_callback = lambda sock, name, ctx: server.sni.append(name)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        server.requests.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    listener = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    server.port = listener.sockets[0].getsockname()[1]
    async with listener:
        yield server, good_pem, other_pem


def _client(server: Server, ca_pem: str) -> SafeHttpClient:
    async def resolve(host: str, port: int) -> list[str]:
        return ["127.0.0.1"]

    return SafeHttpClient(
        EgressPolicy(allowed_ports=frozenset({server.port}), ca_bundle_pem=ca_pem),
        proxy=None,
        resolver=resolve,
    )


@pytest.fixture(autouse=True)
def _reach_the_local_server(monkeypatch: pytest.MonkeyPatch) -> None:
    # Loopback is never allowed in the application; the test server lives there.
    monkeypatch.setattr(safe_http, "is_allowed", lambda address, networks: True)


async def test_pinned_connection_keeps_sni_host_and_certificate_name(
    tls_server: tuple[Server, str, str],
) -> None:
    server, good_pem, _ = tls_server
    response = await _client(server, good_pem).get(f"https://pinned.test:{server.port}/x")
    assert response.text == "ok"
    assert server.sni == ["pinned.test"]
    assert f"host: pinned.test:{server.port}".encode() in server.requests[0].lower()


async def test_certificate_for_another_name_is_refused(
    tls_server: tuple[Server, str, str],
) -> None:
    server, _, other_pem = tls_server
    with pytest.raises(EgressError) as exc:
        await _client(server, other_pem).get(f"https://pinned.test:{server.port}/")
    assert exc.value.code == "network_error"
    assert server.requests == []
