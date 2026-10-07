// Package main implements the AI Jailer guest agent: the only userspace
// process the platform starts inside a cell (PID 1). It serves a small,
// host-initiated request/response protocol over virtio-vsock.
//
// Wire format (matches engine/firecracker.py agent_exec):
//
//	frame   = uint32 big-endian length || JSON object
//	request = {"op": "ping"|"exec"|"put_file"|"get_file", ...}
//	reply   = JSON object; errors are {"error": "<message>"}
//
// The agent never initiates connections: there is no guest->host channel to
// abuse, and health is determined by the host polling "ping".
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxFrame bounds a single frame in either direction (host enforces the same).
	MaxFrame = 16 * 1024 * 1024
	// MaxOutput bounds captured stdout/stderr per stream so a workload cannot
	// exhaust agent memory by printing forever.
	MaxOutput = 4 * 1024 * 1024
)

var errFrameTooLarge = errors.New("frame too large")

// Request is the union of all request fields; unused fields are zero.
type Request struct {
	Op      string `json:"op"`
	Cmd     string `json:"cmd,omitempty"`
	Timeout int    `json:"timeout,omitempty"` // seconds
	User    string `json:"user,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Path    string `json:"path,omitempty"`
	Data    []byte `json:"data,omitempty"` // base64 in JSON
	Mode    uint32 `json:"mode,omitempty"`
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, errFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > MaxFrame {
		return errFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	// Single write so concurrent replies on one conn never interleave.
	_, err = w.Write(append(hdr[:], body...))
	return err
}

func errReply(format string, a ...any) map[string]any {
	return map[string]any{"error": fmt.Sprintf(format, a...)}
}
