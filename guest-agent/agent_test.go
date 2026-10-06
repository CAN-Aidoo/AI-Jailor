package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	// Make this test process adopt orphans like PID 1 would, so group-reaping is testable.
	_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	os.Exit(m.Run())
}

func testCfg() execConfig {
	c := defaultExecConfig()
	c.dropCredentials = false // tests run as an unprivileged or root user; no uid switch
	return c
}

func exec1(t *testing.T, cmd string, mut func(*Request)) map[string]any {
	t.Helper()
	r := &Request{Op: "exec", Cmd: cmd}
	if mut != nil {
		mut(r)
	}
	return runExec(r, testCfg())
}

func TestFrameRoundTripAndLimit(t *testing.T) {
	var b bytes.Buffer
	if err := writeFrame(&b, map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	raw, err := readFrame(&b)
	if err != nil || string(raw) != `{"a":1}` {
		t.Fatalf("got %q %v", raw, err)
	}
	var big bytes.Buffer
	_ = binary.Write(&big, binary.BigEndian, uint32(MaxFrame+1))
	if _, err := readFrame(&big); err != errFrameTooLarge {
		t.Fatalf("want errFrameTooLarge, got %v", err)
	}
}

func TestExecBasics(t *testing.T) {
	r := exec1(t, "echo out; echo err 1>&2; exit 7", nil)
	if r["exit_code"] != 7 || r["stdout"] != "out\n" || r["stderr"] != "err\n" {
		t.Fatalf("unexpected %v", r)
	}
	if r["timed_out"] != false {
		t.Fatal("should not time out")
	}
}

func TestExecEnvIsolated(t *testing.T) {
	t.Setenv("AGENT_SECRET", "hunter2")
	r := exec1(t, "echo ${AGENT_SECRET:-unset}", nil)
	if strings.TrimSpace(r["stdout"].(string)) != "unset" {
		t.Fatalf("agent env leaked: %v", r)
	}
	r = exec1(t, "echo $FOO", func(q *Request) { q.Env = map[string]string{"FOO": "bar"} })
	if strings.TrimSpace(r["stdout"].(string)) != "bar" {
		t.Fatalf("request env not applied: %v", r)
	}
}

func TestTimeoutKillsWholeProcessGroup(t *testing.T) {
	start := time.Now()
	r := exec1(t, "sleep 300 & echo $!; wait", func(q *Request) { q.Timeout = 1 })
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced promptly")
	}
	if r["exit_code"] != 124 || r["timed_out"] != true {
		t.Fatalf("unexpected %v", r)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(r["stdout"].(string)))
	if err != nil {
		t.Fatalf("no child pid in %q", r["stdout"])
	}
	// Child must be dead AND reaped (a zombie would still answer kill(pid,0)).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("background child %d survived or was left as a zombie", pid)
}

func TestBackgroundJobsDoNotOutliveRequest(t *testing.T) {
	r := exec1(t, "sleep 300 & echo $!", nil)
	pid, _ := strconv.Atoi(strings.TrimSpace(r["stdout"].(string)))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("background job %d outlived its request", pid)
}

func TestOutputTruncated(t *testing.T) {
	r := exec1(t, "head -c 6000000 /dev/zero | tr '\\0' a", nil)
	if len(r["stdout"].(string)) != MaxOutput || r["output_truncated"] != true {
		t.Fatalf("len=%d trunc=%v", len(r["stdout"].(string)), r["output_truncated"])
	}
	if r["exit_code"] != 0 {
		t.Fatalf("child must not die from SIGPIPE: %v", r["exit_code"])
	}
}

func TestSignalExitCode(t *testing.T) {
	r := exec1(t, "kill -9 $$", nil)
	if r["exit_code"] != 137 {
		t.Fatalf("want 137 got %v", r["exit_code"])
	}
}

func TestRefusesRootAndUnknownUser(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "passwd")
	gr := filepath.Join(dir, "group")
	_ = os.WriteFile(pw, []byte("root:x:0:0::/root:/bin/sh\nagent:x:1000:1000::/home/agent:/bin/sh\n"), 0o644)
	_ = os.WriteFile(gr, []byte("staff:x:50:agent\nagent:x:1000:\n"), 0o644)
	cfg := defaultExecConfig()
	cfg.passwd, cfg.group = pw, gr
	if r := runExec(&Request{Op: "exec", Cmd: "id", User: "root"}, cfg); r["error"] == nil {
		t.Fatalf("root must be refused: %v", r)
	}
	if r := runExec(&Request{Op: "exec", Cmd: "id", User: "nobody2"}, cfg); r["error"] == nil {
		t.Fatalf("unknown user must be refused: %v", r)
	}
	acc, err := lookupUser("agent", pw, gr)
	if err != nil || acc.uid != 1000 || len(acc.groups) != 2 || acc.groups[1] != 50 {
		t.Fatalf("lookup wrong: %+v %v", acc, err)
	}
}

func TestEmptyCommandAndUnknownOp(t *testing.T) {
	s := newServer(testCfg(), 2)
	if r := s.dispatch(&Request{Op: "exec"}); r["error"] == nil {
		t.Fatal("empty command accepted")
	}
	if r := s.dispatch(&Request{Op: "nope"}); r["error"] == nil {
		t.Fatal("unknown op accepted")
	}
}

func TestConcurrencyLimit(t *testing.T) {
	s := newServer(testCfg(), 1)
	done := make(chan struct{})
	go func() {
		s.dispatch(&Request{Op: "exec", Cmd: "sleep 1"})
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	if r := s.dispatch(&Request{Op: "exec", Cmd: "true"}); r["error"] == nil {
		t.Fatal("second concurrent exec should be rejected")
	}
	<-done
}

func TestFilesRoundTripAndSymlinkSafety(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg()
	p := filepath.Join(dir, "a.txt")
	if r := putFile(&Request{Path: p, Data: []byte("hello"), Mode: 0o600}, cfg); r["error"] != nil {
		t.Fatal(r)
	}
	g := getFile(&Request{Path: p})
	if string(g["data"].([]byte)) != "hello" {
		t.Fatalf("%v", g)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	// A planted symlink must be replaced, not followed.
	victim := filepath.Join(dir, "victim")
	_ = os.WriteFile(victim, []byte("keep"), 0o644)
	link := filepath.Join(dir, "link")
	_ = os.Symlink(victim, link)
	if r := putFile(&Request{Path: link, Data: []byte("pwn")}, cfg); r["error"] != nil {
		t.Fatal(r)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("symlink was followed on write: %q", b)
	}
	// get must refuse a symlink and a FIFO.
	_ = os.Remove(link)
	_ = os.Symlink(victim, link)
	if r := getFile(&Request{Path: link}); r["error"] == nil {
		t.Fatal("get followed symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	_ = syscall.Mkfifo(fifo, 0o600)
	if r := getFile(&Request{Path: fifo}); r["error"] == nil {
		t.Fatal("get opened a FIFO")
	}
	if r := putFile(&Request{Path: "relative", Data: nil}, cfg); r["error"] == nil {
		t.Fatal("relative path accepted")
	}
	if r := putFile(&Request{Path: filepath.Join(dir, "big"), Data: make([]byte, maxFileBytes+1)}, cfg); r["error"] == nil {
		t.Fatal("oversize accepted")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".aj-upload-") {
			t.Fatalf("temp file leaked: %s", e.Name())
		}
	}
}

func dial(t *testing.T) (net.Conn, func()) {
	t.Helper()
	sock := filepath.Join(os.TempDir(), "aj-test-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatInt(time.Now().UnixNano()%1e6, 10)+".sock")
	l, err := listen("unix:" + sock)
	if err != nil {
		t.Fatal(err)
	}
	go newServer(testCfg(), 4).serve(l, nil)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	return c, func() { c.Close(); l.Close(); os.Remove(sock) }
}

func call(t *testing.T, c net.Conn, req any) map[string]any {
	t.Helper()
	if err := writeFrame(c, req); err != nil {
		t.Fatal(err)
	}
	raw, err := readFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestServerSequentialRequestsOnOneConn(t *testing.T) {
	c, done := dial(t)
	defer done()
	if r := call(t, c, map[string]any{"op": "ping"}); r["ok"] != true || r["version"] != version {
		t.Fatalf("%v", r)
	}
	r := call(t, c, map[string]any{"op": "exec", "cmd": "echo hi"})
	if r["stdout"] != "hi\n" || r["exit_code"].(float64) != 0 {
		t.Fatalf("%v", r)
	}
}

func TestServerBadJSONAndOversizeFrameCloseConn(t *testing.T) {
	c, done := dial(t)
	defer done()
	body := []byte("not json")
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)))
	_, _ = c.Write(append(hdr, body...))
	raw, err := readFrame(c)
	if err != nil || !strings.Contains(string(raw), "bad json") {
		t.Fatalf("%q %v", raw, err)
	}
	if _, err := readFrame(c); err == nil {
		t.Fatal("conn should be closed after protocol violation")
	}
	c2, done2 := dial(t)
	defer done2()
	binary.BigEndian.PutUint32(hdr, uint32(MaxFrame+1))
	_, _ = c2.Write(hdr)
	raw, _ = readFrame(c2)
	if !strings.Contains(string(raw), "frame too large") {
		t.Fatalf("%q", raw)
	}
}

// Real uid/gid switch. Needs root to call setuid; skipped otherwise.
func TestDropsToUnprivilegedUserWithNoNewPrivs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to switch uid")
	}
	// t.TempDir parents are 0700; the dropped uid must be able to traverse to its home.
	dir, _ := os.MkdirTemp("", "ajhome")
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0o755)
	pw, gr := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	_ = os.WriteFile(pw, []byte("agent:x:23456:23457::"+dir+":/bin/sh\n"), 0o644)
	_ = os.WriteFile(gr, []byte("agent:x:23457:\n"), 0o644)
	cfg := defaultExecConfig()
	cfg.passwd, cfg.group = pw, gr
	hardenSelf()
	r := runExec(&Request{Op: "exec", Cmd: "id -u; id -g; grep NoNewPrivs /proc/self/status; cd; pwd"}, cfg)
	if r["error"] != nil {
		t.Fatal(r["error"])
	}
	out := r["stdout"].(string)
	for _, want := range []string{"23456\n", "23457\n", "NoNewPrivs:\t1", dir} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}

func TestVsockListenerOptional(t *testing.T) {
	l, err := listenVsock(54321)
	if err != nil {
		t.Skipf("vsock unavailable: %v", err)
	}
	l.Close()
}
