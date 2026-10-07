package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"time"
)

const version = "0.1.0"

type server struct {
	cfg execConfig
	sem chan struct{} // bounds concurrent execs
}

func newServer(cfg execConfig, maxConcurrent int) *server {
	return &server{cfg: cfg, sem: make(chan struct{}, maxConcurrent)}
}

func (s *server) dispatch(req *Request) map[string]any {
	switch req.Op {
	case "ping":
		return map[string]any{"ok": true, "version": version, "time": time.Now().Unix()}
	case "exec":
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			return errReply("too many concurrent executions")
		}
		return runExec(req, s.cfg)
	case "put_file":
		return putFile(req, s.cfg)
	case "get_file":
		return getFile(req)
	default:
		return errReply("unknown op %q", req.Op)
	}
}

// handle serves one connection: any number of sequential request/reply pairs.
func (s *server) handle(c net.Conn) {
	defer c.Close()
	for {
		raw, err := readFrame(c)
		if err != nil {
			if err != io.EOF {
				_ = writeFrame(c, errReply("bad frame: %v", err))
			}
			return
		}
		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			_ = writeFrame(c, errReply("bad json: %v", err))
			return
		}
		if err := writeFrame(c, s.dispatch(&req)); err != nil {
			log.Printf("reply failed: %v", err)
			return
		}
	}
}

// serve accepts until the listener closes. accept errors are logged but never
// fatal: PID 1 must not exit.
func (s *server) serve(l net.Listener, allow func(net.Conn) bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if allow != nil && !allow(c) {
			c.Close()
			continue
		}
		go s.handle(c)
	}
}
