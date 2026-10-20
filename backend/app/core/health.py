"""Liveness and readiness probes."""

from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel
from sqlalchemy import text

from app.core.access import public_endpoint
from app.core.logging import get_logger

router = APIRouter(tags=["health"], dependencies=[Depends(public_endpoint)])
log = get_logger(__name__)


class HealthOut(BaseModel):
    status: Literal["ok"]
    service: str


class ReadinessOut(BaseModel):
    status: Literal["ready", "unavailable"]


@router.get("/healthz", response_model=HealthOut)
async def healthz(request: Request) -> HealthOut:
    return HealthOut(status="ok", service=request.app.state.audience)


@router.get("/readyz", response_model=ReadinessOut)
async def readyz(request: Request, response: Response) -> ReadinessOut:
    """Checks PostgreSQL and Redis. Failure details go to the logs only."""
    try:
        async with request.app.state.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await request.app.state.redis.ping()
    except Exception as exc:
        log.warning("readiness_check_failed", error_type=type(exc).__name__)
        response.status_code = 503
        return ReadinessOut(status="unavailable")
    return ReadinessOut(status="ready")
