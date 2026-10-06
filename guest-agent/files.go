package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maxFileBytes = 12 * 1024 * 1024 // base64 inflation must fit in MaxFrame

func cleanAbs(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	return filepath.Clean(p), nil
}

// putFile writes atomically: a temp file in the same directory, then rename.
// rename replaces a planted symlink at the destination instead of following it,
// so a workload cannot redirect a host-initiated write onto another guest file.
func putFile(req *Request, cfg execConfig) map[string]any {
	path, err := cleanAbs(req.Path)
	if err != nil {
		return errReply("%v", err)
	}
	if len(req.Data) > maxFileBytes {
		return errReply("file too large")
	}
	mode := os.FileMode(req.Mode & 0o777)
	if mode == 0 {
		mode = 0o644
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aj-upload-*")
	if err != nil {
		return errReply("create: %v", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(req.Data); err != nil {
		tmp.Close()
		cleanup()
		return errReply("write: %v", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return errReply("chmod: %v", err)
	}
	if cfg.dropCredentials {
		name := req.User
		if name == "" {
			name = "agent"
		}
		if acc, err := lookupUser(name, cfg.passwd, cfg.group); err == nil {
			_ = tmp.Chown(int(acc.uid), int(acc.gid))
		}
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return errReply("close: %v", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return errReply("rename: %v", err)
	}
	return map[string]any{"ok": true, "bytes": len(req.Data)}
}

// getFile refuses symlinks at the final component and anything that is not a
// regular file (no devices, FIFOs or sockets that could block the agent).
func getFile(req *Request) map[string]any {
	path, err := cleanAbs(req.Path)
	if err != nil {
		return errReply("%v", err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errReply("open: %v", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return errReply("stat: %v", err)
	}
	if !st.Mode().IsRegular() {
		return errReply("not a regular file")
	}
	if st.Size() > maxFileBytes {
		return errReply("file too large")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return errReply("read: %v", err)
	}
	if len(data) > maxFileBytes {
		return errReply("file too large")
	}
	return map[string]any{"data": data, "size": len(data), "mode": fmt.Sprintf("%o", st.Mode().Perm())}
}
