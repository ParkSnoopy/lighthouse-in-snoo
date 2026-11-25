# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder

ARG VERSION=0.1.0
ARG LIGHTHOUSE_STUN_DOMAIN=""
ARG LIGHTHOUSE_STUN_PORT=5349
ARG LIGHTHOUSE_HUB_ORIGIN=""

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w -X main.appVersion=${VERSION} -X main.defaultSTUNDomain=${LIGHTHOUSE_STUN_DOMAIN} -X main.defaultSTUNPort=${LIGHTHOUSE_STUN_PORT} -X main.defaultHubOrigin=${LIGHTHOUSE_HUB_ORIGIN}" \
    -o /out/lighthouse ./cmd/lighthouse

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=0.1.0

LABEL org.opencontainers.image.title="lighthouse" \
      org.opencontainers.image.description="WebRTC Lighthouse hub (TLS 1.3 WSS + DTLS 1.3 UDP STUNS/TURNS)" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=builder /out/lighthouse /usr/local/bin/lighthouse

USER 10001:10001
EXPOSE 8443/tcp
EXPOSE 5349/udp

ENTRYPOINT ["/usr/local/bin/lighthouse"]
CMD ["hub"]
