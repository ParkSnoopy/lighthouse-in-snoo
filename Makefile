VERSION := $(shell sed -n 's/^const Version = "\(.*\)"/\1/p' cmd/lighthouse/version.go)
IMAGE ?= lighthouse:$(VERSION)

LDFLAGS := -s -w

.PHONY: build test vet version docker-build

build:
	CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/lighthouse ./cmd/lighthouse

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

version:
	@echo $(VERSION)

docker-build:
	docker build \
		--platform linux/amd64 \
		-t "$(IMAGE)" .
