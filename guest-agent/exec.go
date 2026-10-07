package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// limitedBuffer keeps at most max bytes and records truncation. Writes always
// report success so the child is never blocked or killed by SIGPIPE.
type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := l.max - l.buf.Len()
	if room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
			l.truncated = true
		} else {
			l.buf.Write(p)
		}
	} else if len(p) > 0 {
		l.truncated = true
	}
	return len(p), nil
}

type execConfig struct {
	passwd, group string
	shell         string
	allowRoot     bool
	// dropCredentials is false only in unit tests that cannot change uid.
	dropCredentials bool
}

func defaultExecConfig() execConfig {
	return execConfig{passwd: "/etc/passwd", group: "/etc/group", shell: "/bin/sh", dropCredentials: true}
}

const (
	defaultTimeout = 30
	maxTimeout     = 24 * 60 * 60
)

func runExec(req *Request, cfg execConfig) map[string]any {
	if req.Cmd == "" {
		return errReply("empty command")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	userName := req.User
	if userName == "" {
		userName = "agent"
	}
	var acc *account
	if cfg.dropCredentials {
		var err error
		acc, err = lookupUser(userName, cfg.passwd, cfg.group)
		if err != nil {
			return errReply("%v", err)
		}
		if acc.uid == 0 && !cfg.allowRoot {
			return errReply("refusing to run workload as root")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	cmd := exec.Command(cfg.shell, "-c", req.Cmd)
	// Kill the whole process group on timeout, not just the shell, so
	// backgrounded children cannot outlive the request.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	home := "/tmp"
	if acc != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: acc.uid, Gid: acc.gid, Groups: acc.groups}
		home = acc.home
	}
	if req.Cwd != "" {
		// Relative paths would resolve against the agent's own directory ("/" as PID 1), which no caller
		// means; a NUL cannot be passed to chdir. Whether the directory exists, and whether the user may
		// enter it, is only known when the command starts and is reported then.
		if !filepath.IsAbs(req.Cwd) {
			return errReply("working directory %q must be an absolute path", req.Cwd)
		}
		if strings.IndexByte(req.Cwd, 0) >= 0 {
			return errReply("working directory contains a NUL byte")
		}
	}
	cmd.Dir = req.Cwd
	if cmd.Dir == "" {
		if st, err := os.Stat(home); err == nil && st.IsDir() {
			cmd.Dir = home
		} else {
			cmd.Dir = "/"
		}
	}
	// Minimal, explicit environment: nothing from the agent's own env leaks in.
	env, err := buildEnv(req.Env, home, userName)
	if err != nil {
		return errReply("%v", err)
	}
	cmd.Env = env
	stdout := &limitedBuffer{max: MaxOutput}
	stderr := &limitedBuffer{max: MaxOutput}
	// Hand the child raw pipe fds (not io.Writers): with writers, cmd.Wait blocks
	// until EVERY holder of the pipe exits, so a backgrounded job would pin the
	// request until its timeout. We drain the pipes ourselves instead.
	outR, outW, err := os.Pipe()
	if err != nil {
		return errReply("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		return errReply("pipe: %v", err)
	}
	cmd.Stdout, cmd.Stderr = outW, errW

	start := time.Now()
	if err := cmd.Start(); err != nil {
		outR.Close()
		outW.Close()
		errR.Close()
		errW.Close()
		// A failed chdir into the working directory is reported by os/exec against the program ("fork/exec
		// /bin/sh: no such file or directory"), which reads as if the shell were missing. If the shell exists
		// and a directory was asked for, the directory is the cause: say so and name it.
		if req.Cwd != "" {
			var errno syscall.Errno
			if _, serr := os.Stat(cfg.shell); serr == nil && errors.As(err, &errno) {
				return errReply("cannot start in working directory %q: %v", req.Cwd, errno)
			}
		}
		return errReply("start failed: %v", err)
	}
	outW.Close()
	errW.Close()
	var drain sync.WaitGroup
	drain.Add(2)
	go func() { defer drain.Done(); _, _ = io.Copy(stdout, outR) }()
	go func() { defer drain.Done(); _, _ = io.Copy(stderr, errR) }()
	pgid := cmd.Process.Pid
	trackPID(pgid, true)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timedOut := false
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		timedOut = true
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		waitErr = <-done
	}
	trackPID(pgid, false)
	// Kill anything left in the group even on normal exit (background jobs), then
	// reap the orphans that were re-parented to us.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	reapGroup(pgid)
	// Writers are dead once the group is killed, so EOF is normally immediate.
	// A daemon that escaped the group (setsid) could still hold the pipe: bound the wait.
	drained := make(chan struct{})
	go func() { drain.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(500 * time.Millisecond):
		outR.Close()
		errR.Close()
		<-drained
	}
	outR.Close()
	errR.Close()

	exit := 0
	var cpuMS, rssMB int64
	if ps := cmd.ProcessState; ps != nil {
		exit = ps.ExitCode()
		if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
			cpuMS = ru.Utime.Sec*1000 + int64(ru.Utime.Usec)/1000 + ru.Stime.Sec*1000 + int64(ru.Stime.Usec)/1000
			rssMB = ru.Maxrss / 1024 // Linux reports KiB
		}
		if exit == -1 { // killed by signal
			if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				exit = 128 + int(ws.Signal())
			}
		}
	}
	var ee *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &ee) {
		return errReply("wait failed: %v", waitErr)
	}
	if timedOut {
		exit = 124
	}
	return map[string]any{
		"exit_code":        exit,
		"stdout":           stdout.buf.String(),
		"stderr":           stderr.buf.String(),
		"duration_ms":      time.Since(start).Milliseconds(),
		"cpu_ms":           cpuMS,
		"memory_peak_mb":   rssMB,
		"timed_out":        timedOut,
		"output_truncated": stdout.truncated || stderr.truncated,
	}
}

// validEnvName reports whether name is a portable environment variable name. A name containing '=' would
// make "k=v" ambiguous (a different variable than the one that was asked for), and an empty or NUL-bearing
// one cannot be passed to execve at all.
func validEnvName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// buildEnv returns the command's environment: the agent's defaults, overridden by the request's variables.
// Names are validated (see validEnvName), each appears exactly once and the order is fixed. (os/exec would
// also drop duplicates, keeping the last, but building from a map makes the precedence explicit here.)
// HOME and USER belong to the account the command runs as and cannot be overridden.
func buildEnv(req map[string]string, home, userName string) ([]string, error) {
	m := map[string]string{"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
	for k, v := range req {
		if !validEnvName(k) {
			return nil, fmt.Errorf("invalid environment variable name %q", k)
		}
		if strings.IndexByte(v, 0) >= 0 {
			return nil, fmt.Errorf("the value of %s contains a NUL byte", k)
		}
		if k == "HOME" || k == "USER" {
			return nil, fmt.Errorf("environment variable %s is set by the agent and cannot be overridden", k)
		}
		m[k] = v
	}
	m["HOME"], m["USER"] = home, userName
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out, nil
}
