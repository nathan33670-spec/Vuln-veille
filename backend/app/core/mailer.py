"""Outgoing e-mail. The API never talks SMTP itself: messages are queued to a worker."""

import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Protocol

from app.core.config import Settings
from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class Mail:
    to: str
    subject: str
    body: str


class Mailer(Protocol):
    def send(self, mail: Mail) -> None: ...


@dataclass
class MemoryMailer:
    """Test double collecting messages."""

    outbox: list[Mail] = field(default_factory=list)

    def send(self, mail: Mail) -> None:
        self.outbox.append(mail)


class NullMailer:
    """Development without SMTP: messages are dropped. Bodies carry one-time links,
    so they are never logged."""

    def send(self, mail: Mail) -> None:
        log.warning("email_not_sent_no_smtp", subject=mail.subject)


class QueueMailer:
    def send(self, mail: Mail) -> None:
        from app.worker import send_email  # noqa: PLC0415 - avoid importing Celery at app import

        send_email.delay(mail.to, mail.subject, mail.body)


def deliver_smtp(settings: Settings, mail: Mail) -> None:
    if not settings.smtp_host:
        NullMailer().send(mail)
        return
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = mail.to
    message["Subject"] = mail.subject
    message.set_content(mail.body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
        if settings.smtp_starttls:
            smtp.starttls(context=ssl.create_default_context())
        if settings.smtp_username and settings.smtp_password:
            smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
        smtp.send_message(message)


def mailer_for(settings: Settings) -> Mailer:
    return QueueMailer() if settings.smtp_host else NullMailer()
