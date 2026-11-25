VERSION := $(shell sed -n 's/^const Version = "\(.*\)"/\1/p' pkg/version/version.go)
IMAGE ?= lighthouse:$(VERSION)

LDFLAGS := -s -w
UI_BUILD_TAGS ?= $(shell pkg-config --exists xxf86vm 2>/dev/null || echo "-tags wayland")

SECURITY_PKGS := \
	./pkg/identity/... \
	./pkg/protocol/... \
	./pkg/peer/... \
	./pkg/tun/... \
	./internal/hub/... \
	./internal/jcs/... \
	./internal/ratelimit/... \
	./internal/stunserver/... \
	./internal/turnserver/...

.PHONY: build build-ui test vet lint version docker-build

build:
	CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/lighthouse ./cmd/lighthouse

build-ui:
	go build $(UI_BUILD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o bin/lighthouse-ui ./cmd/lighthouse-ui

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	go vet ./...
	go tool gocritic check ./...
	go tool gocritic check -enableAll $(SECURITY_PKGS)

version:
	@echo $(VERSION)

docker-build:
	docker build \
		--platform linux/amd64 \
		-t "$(IMAGE)" .
