# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w" \
    -o /out/lighthouse ./cmd/lighthouse

FROM debian:13-slim

LABEL org.opencontainers.image.title="lighthouse" \
      org.opencontainers.image.description="WebRTC Lighthouse hub (TLS 1.3 WSS + DTLS 1.3 UDP / optional TLS 1.3 TCP STUNS/TURNS)"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 -r lighthouse && \
    useradd -u 10001 -g lighthouse -r -s /usr/sbin/nologin -M lighthouse && \
    mkdir -p /etc/lighthouse && \
    chown 10001:10001 /etc/lighthouse && \
    chmod 0750 /etc/lighthouse

COPY --from=builder /out/lighthouse /usr/local/bin/lighthouse

USER 10001:10001
VOLUME ["/etc/lighthouse"]
EXPOSE 8443/tcp
EXPOSE 5349/udp
EXPOSE 5349/tcp

ENTRYPOINT ["/usr/local/bin/lighthouse"]
CMD ["hub"]
