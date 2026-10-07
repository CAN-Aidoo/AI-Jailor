# Static, cgo-free, reproducible-ish build of the guest agent.
GOFLAGS_REL = -trimpath -ldflags="-s -w"

.PHONY: build test rootfs-install
build:
	CGO_ENABLED=0 go build $(GOFLAGS_REL) -o dist/aijailer-agent .
	CGO_ENABLED=0 go build $(GOFLAGS_REL) -o dist/aijailer-peer ./cmd/aijailer-peer

test:
	go vet ./...
	CGO_ENABLED=0 go test -count=1 ./...   # the production build flavour: no_new_privs tests run here
	go test -race -count=1 ./...            # race detector needs cgo: no_new_privs tests skip

# Usage: make rootfs-install ROOTFS_MNT=/mnt/rootfs   (rootfs mounted rw)
rootfs-install: build
	install -D -m 0755 dist/aijailer-agent $(ROOTFS_MNT)/sbin/aijailer-agent
	install -D -m 0755 dist/aijailer-peer $(ROOTFS_MNT)/usr/sbin/aijailer-peer
