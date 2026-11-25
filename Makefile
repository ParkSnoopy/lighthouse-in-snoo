-include .env
export

VERSION ?= $(shell tr -d '[:space:]' < VERSION)
LIGHTHOUSE_STUN_DOMAIN ?=
LIGHTHOUSE_STUN_PORT ?= 3478
LIGHTHOUSE_HUB_ORIGIN ?=
LIGHTHOUSE_IMAGE ?= lighthouse:$(VERSION)

LDFLAGS := -s -w \
	-X main.appVersion=$(VERSION) \
	-X main.defaultSTUNDomain=$(LIGHTHOUSE_STUN_DOMAIN) \
	-X main.defaultSTUNPort=$(LIGHTHOUSE_STUN_PORT) \
	-X main.defaultHubOrigin=$(LIGHTHOUSE_HUB_ORIGIN)

.PHONY: build test vet version docker-build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/lighthouse ./cmd/lighthouse

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

version:
	@echo $(VERSION)

docker-build:
	docker build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg LIGHTHOUSE_STUN_DOMAIN="$(LIGHTHOUSE_STUN_DOMAIN)" \
		--build-arg LIGHTHOUSE_STUN_PORT="$(LIGHTHOUSE_STUN_PORT)" \
		--build-arg LIGHTHOUSE_HUB_ORIGIN="$(LIGHTHOUSE_HUB_ORIGIN)" \
		-t "$(LIGHTHOUSE_IMAGE)" .
