package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const hostCID = 2 // VMADDR_CID_HOST

// vsockListener accepts only connections whose peer is the host (CID 2).
// Firecracker's vsock device can only reach the host anyway; this is
// belt-and-braces against a misconfigured device model.
type vsockListener struct {
	fd   int
	port uint32
}

func listenVsock(port uint32) (*vsockListener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock bind: %w", err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock listen: %w", err)
	}
	return &vsockListener{fd: fd, port: port}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) {
	for {
		nfd, sa, err := unix.Accept4(l.fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if err == unix.EINTR || err == unix.ECONNABORTED {
				continue
			}
			return nil, err
		}
		if vm, ok := sa.(*unix.SockaddrVM); !ok || vm.CID != hostCID {
			unix.Close(nfd)
			continue
		}
		f := os.NewFile(uintptr(nfd), "vsock-conn")
		c, err := net.FileConn(f)
		f.Close() // FileConn dups the descriptor
		if err != nil {
			continue
		}
		return c, nil
	}
}

func (l *vsockListener) Close() error   { return unix.Close(l.fd) }
func (l *vsockListener) Addr() net.Addr { return vsockAddr(l.port) }

type vsockAddr uint32

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return "vsock:" + strconv.Itoa(int(a)) }

// listen parses "vsock:<port>" or "unix:<path>" (the latter for tests and
// local development; never used inside a production cell).
func listen(spec string) (net.Listener, error) {
	kind, arg, ok := strings.Cut(spec, ":")
	if !ok {
		return nil, fmt.Errorf("bad listen spec %q", spec)
	}
	switch kind {
	case "vsock":
		p, err := strconv.ParseUint(arg, 10, 32)
		if err != nil {
			return nil, err
		}
		return listenVsock(uint32(p))
	case "unix":
		_ = os.Remove(arg)
		l, err := net.Listen("unix", arg)
		if err == nil {
			_ = os.Chmod(arg, 0o600)
		}
		return l, err
	}
	return nil, fmt.Errorf("unsupported listen kind %q", kind)
}
