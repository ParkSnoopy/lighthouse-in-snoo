# syntax=docker/dockerfile:1
FROM scratch AS gomod-cache
FROM scratch AS apt-cache

FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=bind,from=gomod-cache,source=/,target=/cache-gomod \
    --mount=type=cache,target=/go/pkg/mod \
    if [ -d /cache-gomod/cache/download ]; then \
      cp -a /cache-gomod/. /go/pkg/mod/; \
    fi && \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w" \
    -o /out/lighthouse ./cmd/lighthouse

FROM debian:13-slim

LABEL org.opencontainers.image.title="lighthouse" \
      org.opencontainers.image.description="WebRTC Lighthouse hub (TLS 1.3 WSS + DTLS 1.3 UDP / optional TLS 1.3 TCP STUNS/TURNS)"

RUN --mount=type=bind,from=apt-cache,source=/,target=/cache-apt \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache && \
    if ls /cache-apt/archives/*.deb >/dev/null 2>&1; then \
      mkdir -p /var/cache/apt/archives && \
      cp -n /cache-apt/archives/*.deb /var/cache/apt/archives/; \
    fi && \
    if [ -d /cache-apt/lists ] && [ -n "$(find /cache-apt/lists -maxdepth 1 -type f 2>/dev/null)" ]; then \
      mkdir -p /var/lib/apt/lists && \
      find /cache-apt/lists -maxdepth 1 -type f -exec cp -n {} /var/lib/apt/lists/ \; && \
      apt-get install -y --no-install-recommends --no-download ca-certificates || \
      (apt-get update && apt-get install -y --no-install-recommends ca-certificates); \
    else \
      apt-get update && \
      apt-get install -y --no-install-recommends ca-certificates; \
    fi

RUN groupadd -g 10001 -r lighthouse && \
    useradd -u 10001 -g lighthouse -r -s /usr/sbin/nologin -M lighthouse && \
    mkdir -p /etc/lighthouse && \
    chown 10001:10001 /etc/lighthouse && \
    chmod 0750 /etc/lighthouse

COPY --from=builder /out/lighthouse /usr/local/bin/lighthouse

USER 10001:10001
VOLUME ["/etc/lighthouse"]
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/lighthouse"]
CMD ["hub"]
