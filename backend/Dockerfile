# syntax=docker/dockerfile:1
# Backend image: back-office API, portal API, workers, scheduler and admin CLI.
# Base images are pinned by digest; refresh them deliberately (PROCEDURES.md §8).

FROM ghcr.io/astral-sh/uv:0.11.30@sha256:93b61e21202b1dab861092748e46bbd6e0e41dd84f59b9174efd2353186e1b47 AS uv

FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app

FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641 AS runtime
# pip (and the libraries it vendors) is not needed at runtime: remove it to shrink the attack surface.
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-* \
           /usr/local/lib/python3.13/ensurepip /usr/local/bin/pip /usr/local/bin/pip3* \
 && groupadd --system --gid 10001 vv \
 && useradd --system --uid 10001 --gid vv --no-create-home --shell /usr/sbin/nologin vv
WORKDIR /app
# Code is owned by root and read-only for the runtime user.
COPY --from=build /app /app
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main_backoffice:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
