"""RFC 9457 problem details. Clients get generic messages; details stay in the logs."""

from http import HTTPStatus
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import get_logger

PROBLEM_JSON = "application/problem+json"

log = get_logger(__name__)


class ProblemDetail(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None
    request_id: str | None = None
    errors: list[dict[str, Any]] | None = None


def problem_response(
    request: Request,
    status: int,
    detail: str | None = None,
    errors: list[dict[str, Any]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    problem = ProblemDetail(
        title=HTTPStatus(status).phrase,
        status=status,
        detail=detail,
        instance=request.url.path,
        request_id=getattr(request.state, "request_id", None),
        errors=errors,
    )
    return JSONResponse(
        problem.model_dump(exclude_none=True),
        status_code=status,
        media_type=PROBLEM_JSON,
        headers=headers,
    )


async def _http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # pragma: no cover - registration guarantees it
        raise exc
    is_client_error = exc.status_code < HTTPStatus.INTERNAL_SERVER_ERROR
    detail = exc.detail if isinstance(exc.detail, str) and is_client_error else None
    return problem_response(request, exc.status_code, detail, headers=exc.headers)


async def _validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        raise exc
    # Never echo submitted values back: they may contain secrets or attack payloads.
    errors = [
        {"loc": list(err.get("loc", ())), "type": err.get("type", "invalid")}
        for err in exc.errors()
    ]
    return problem_response(request, 422, "Invalid request.", errors=errors)


class UnhandledErrorMiddleware:
    """Turns unhandled exceptions into a generic 500 problem.

    Installed inside the other middlewares (unlike Starlette's outermost error
    handler) so that the response still gets the request id and security headers.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            log.error("unhandled_exception", path=scope.get("path"), exc_info=exc)
            if response_started:
                raise
            response = problem_response(Request(scope), 500)
            await response(scope, receive, send)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_exception_handler)
