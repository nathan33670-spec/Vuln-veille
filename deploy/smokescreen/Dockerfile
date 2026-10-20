# syntax=docker/dockerfile:1
# Egress proxy (Stripe smokescreen): every outbound request from the workers goes
# through it; private and metadata ranges are always refused (ADR-012).
# Built from source with a patched Go toolchain and security-bumped dependencies
# (upstream v0.1.0 pins vulnerable x/net, x/text and logrus versions).

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
WORKDIR /build
RUN go mod init vuln-veille/smokescreen-build \
 && go get github.com/stripe/smokescreen@v0.1.0 \
           golang.org/x/net@v0.60.0 \
           golang.org/x/text@v0.42.0 \
           github.com/sirupsen/logrus@v1.9.3 \
 && go build -ldflags="-s -w" -o /out/smokescreen github.com/stripe/smokescreen

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10003 smokescreen && adduser -S -u 10003 -G smokescreen -H smokescreen
COPY --from=build /out/smokescreen /usr/local/bin/smokescreen
COPY acl.yaml config.yaml /etc/smokescreen/
USER 10003:10003
EXPOSE 4750
ENTRYPOINT ["smokescreen", "--listen-ip=0.0.0.0", "--listen-port=4750", "--config-file=/etc/smokescreen/config.yaml"]
