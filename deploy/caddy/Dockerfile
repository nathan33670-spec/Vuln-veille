# syntax=docker/dockerfile:1
# Reverse proxy image: TLS, security headers, and the two SPAs as static files.
# Build context: repository root.
#
# Caddy is compiled from source with a patched Go toolchain and x/net, because the
# upstream image may lag behind Go security releases. Dependencies are pinned in
# build/go.mod and build/go.sum: the build verifies every module against go.sum and
# never resolves versions itself. Bump procedure: docs/PROCEDURES.md §8.

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS caddy
ENV CGO_ENABLED=0 GOFLAGS="-trimpath -mod=readonly" GOTOOLCHAIN=local
WORKDIR /build
COPY deploy/caddy/build/go.mod deploy/caddy/build/go.sum ./
RUN go mod download
COPY deploy/caddy/build/main.go ./
RUN go build -ldflags="-s -w" -o /out/caddy .

FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS spa
RUN corepack enable
WORKDIR /src
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
COPY frontend/apps/backoffice/package.json apps/backoffice/
COPY frontend/apps/portal/package.json apps/portal/
COPY frontend/packages/ui/package.json packages/ui/
COPY frontend/packages/api-client/package.json packages/api-client/
COPY frontend/packages/auth/package.json packages/auth/
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates mailcap \
 && addgroup -S -g 10002 caddy && adduser -S -u 10002 -G caddy -H caddy \
 && mkdir -p /data /config /etc/caddy && chown -R 10002:10002 /data /config
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
COPY --from=caddy /out/caddy /usr/local/bin/caddy
COPY deploy/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=spa /src/apps/backoffice/dist /srv/backoffice
COPY --from=spa /src/apps/portal/dist /srv/portal
USER 10002:10002
EXPOSE 8080 8443
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
