# Static, cgo-free, reproducible-ish build of the guest agent.
GOFLAGS_REL = -trimpath -ldflags="-s -w"

.PHONY: build test rootfs-install
build:
	CGO_ENABLED=0 go build $(GOFLAGS_REL) -o dist/aijailer-agent .

test:
	go vet ./... && go test -race -count=1 ./...

# Usage: make rootfs-install ROOTFS_MNT=/mnt/rootfs   (rootfs mounted rw)
rootfs-install: build
	install -D -m 0755 dist/aijailer-agent $(ROOTFS_MNT)/sbin/aijailer-agent
