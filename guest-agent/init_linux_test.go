package main

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// inFreshNetns runs fn on a thread that lives in a brand-new network namespace, where lo starts DOWN
// exactly like in a freshly booted guest. The thread is never unlocked, so it exits with the goroutine
// instead of returning to the pool inside a foreign namespace. Skips where unshare is not permitted.
func inFreshNetns(t *testing.T, fn func()) {
	t.Helper()
	res := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			res <- err
			return
		}
		fn()
		res <- nil
	}()
	if err := <-res; err != nil {
		t.Skipf("cannot create a network namespace here: %v", err)
	}
}

// loopbackRoundTrip listens on 127.0.0.1, connects to it and echoes one message.
func loopbackRoundTrip() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_, _ = io.Copy(c, c)
			c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	_, err = io.ReadFull(c, buf)
	return err
}

func TestBringUpLoopbackMakesLocalhostReachable(t *testing.T) {
	inFreshNetns(t, func() {
		if err := loopbackRoundTrip(); err == nil {
			t.Errorf("precondition: localhost already works with lo down, so this test proves nothing")
			return
		}
		if err := bringUpLoopback(); err != nil {
			t.Errorf("bringUpLoopback: %v", err)
			return
		}
		if err := loopbackRoundTrip(); err != nil {
			t.Errorf("localhost still unreachable after bringUpLoopback: %v", err)
		}
	})
}

func TestBringUpLoopbackIsIdempotent(t *testing.T) {
	inFreshNetns(t, func() {
		for i := 0; i < 3; i++ {
			if err := bringUpLoopback(); err != nil {
				t.Errorf("call %d: %v", i+1, err)
				return
			}
		}
		if err := loopbackRoundTrip(); err != nil {
			t.Errorf("localhost unreachable: %v", err)
		}
	})
}

func TestBringUpLoopbackReportsFailureInsteadOfPretendingToSucceed(t *testing.T) {
	inFreshNetns(t, func() {
		// Drop CAP_NET_ADMIN from this (locked) thread only: the ioctl must now fail, and say so.
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		if err := unix.Capget(&hdr, &data[0]); err != nil {
			t.Errorf("capget: %v", err)
			return
		}
		data[0].Effective &^= 1 << unix.CAP_NET_ADMIN
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			t.Errorf("capset: %v", err)
			return
		}
		if err := bringUpLoopback(); err == nil {
			t.Errorf("bringUpLoopback returned nil without CAP_NET_ADMIN")
		}
	})
}
