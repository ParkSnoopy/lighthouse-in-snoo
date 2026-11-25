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

.PHONY: build build-ui icons install-linux-desktop package-macos test vet lint version docker-build

build:
	CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/lighthouse ./cmd/lighthouse

build-ui:
	go build $(UI_BUILD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o bin/lighthouse-ui ./cmd/lighthouse-ui

icons:
	go run ./scripts/gen_platform_icons.go

install-linux-desktop:
	@DATA_HOME="$${XDG_DATA_HOME:-$$HOME/.local/share}"; \
	for sz in 16 32 48 64 128 256 512; do \
		install -Dm644 "assets/icon/hicolor/$${sz}x$${sz}/apps/us.ireh.lighthouse.png" \
			"$$DATA_HOME/icons/hicolor/$${sz}x$${sz}/apps/us.ireh.lighthouse.png"; \
	done; \
	install -Dm644 assets/packaging/linux/us.ireh.lighthouse.desktop "$$DATA_HOME/applications/us.ireh.lighthouse.desktop"

package-macos: build-ui
	@APP="bin/Lighthouse.app"; \
	mkdir -p "$$APP/Contents/MacOS" "$$APP/Contents/Resources"; \
	cp bin/lighthouse-ui "$$APP/Contents/MacOS/lighthouse-ui"; \
	cp assets/packaging/macos/Info.plist "$$APP/Contents/Info.plist"; \
	cp assets/icon/lighthouse-in-snoo.icns "$$APP/Contents/Resources/lighthouse-in-snoo.icns"

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
