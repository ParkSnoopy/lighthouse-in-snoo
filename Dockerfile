# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/lighthouse ./cmd/lighthouse

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/lighthouse /usr/local/bin/lighthouse

USER 10001:10001
EXPOSE 8443/tcp
EXPOSE 3478/udp

ENTRYPOINT ["/usr/local/bin/lighthouse"]
