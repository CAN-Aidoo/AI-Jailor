// aijailer-peer: connect this cell to its peer over an attested, end-to-end encrypted link.
//
//	aijailer-peer --link <32 hex> --stdio
//	aijailer-peer --link <32 hex> --listen 127.0.0.1:7000
//
// The link must have been proposed and accepted through the platform API. The helper reaches the
// platform relay through the cell's own egress proxy (HTTPS_PROXY), verifies the platform's
// attestation of the PEER's certificate (AIJAILER_PEER_ATTEST_PUBKEY, injected by the platform), runs
// mutual TLS 1.3 to the peer THROUGH the relay, and then bridges the encrypted channel to stdio or
// to ONE local connection, so the workload (any language) just reads and writes a plain socket and
// plaintext never leaves the guest.
//
// Identity: by default each run makes a fresh ephemeral certificate and trusts the platform's
// attestation of the peer. To not depend on the platform for identity at all, give each side a
// persistent identity (--identity-file, whose certificate hash is stable and printed in the
// "established" event and by --cert-hash-file), exchange the two hashes out of band, and pass the
// other side's hash as --pin. A pinned peer cannot be impersonated even by the platform.
//
// Status goes to stderr as one JSON object per line. Exit: 0 ok, 2 usage, 3 proxy refused,
// 4 attestation rejected, 5 TLS failed, 6 other.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/can-aidoo/ai-jailor/guest-agent/internal/peer"
)

func emit(v map[string]any) {
	b, _ := json.Marshal(v)
	fmt.Fprintln(os.Stderr, string(b))
}

func die(code int, msg string, err error) {
	emit(map[string]any{"event": "error", "message": msg, "detail": fmt.Sprint(err)})
	os.Exit(code)
}

func proxyAddr(flagVal string) string {
	raw := flagVal
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if raw == "" {
			raw = os.Getenv(k)
		}
	}
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

func main() {
	link := flag.String("link", "", "peer link id (32 hex characters)")
	stdio := flag.Bool("stdio", false, "bridge the encrypted channel to stdin/stdout")
	listen := flag.String("listen", "", "bridge to ONE local TCP connection on this address (e.g. 127.0.0.1:7000)")
	proxy := flag.String("proxy", "", "egress proxy (default: HTTPS_PROXY)")
	pubkey := flag.String("pubkey", os.Getenv("AIJAILER_PEER_ATTEST_PUBKEY"), "platform attestation public key, base64 (default: env AIJAILER_PEER_ATTEST_PUBKEY)")
	pin := flag.String("pin", "", "expected sha256 (hex) of the peer's certificate, agreed out of band")
	wait := flag.Duration("wait", 90*time.Second, "how long to wait for the peer")
	certHashFile := flag.String("cert-hash-file", "", "write the sha256 of OUR certificate here before connecting")
	identityFile := flag.String("identity-file", "", "persistent identity (certificate+key, created on first use): stable hash for out-of-band pinning")
	flag.Parse()

	if len(*link) != 32 || (!*stdio && *listen == "") || (*stdio && *listen != "") {
		fmt.Fprintln(os.Stderr, "usage: aijailer-peer --link <32 hex> (--stdio | --listen ADDR) [--pin HEX] [--wait 90s]")
		os.Exit(2)
	}
	pk, err := base64.StdEncoding.DecodeString(*pubkey)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		die(2, "platform public key missing or malformed (AIJAILER_PEER_ATTEST_PUBKEY / --pubkey)", err)
	}
	addr := proxyAddr(*proxy)
	if addr == "" {
		die(2, "no egress proxy configured (HTTPS_PROXY / --proxy)", errors.New("empty"))
	}

	var ln net.Listener
	if *listen != "" { // listen first so the workload can connect early; it waits in the backlog
		if ln, err = net.Listen("tcp", *listen); err != nil {
			die(6, "cannot listen", err)
		}
		emit(map[string]any{"event": "listening", "addr": ln.Addr().String()})
	}

	var id *peer.Identity
	if *identityFile != "" {
		id, err = peer.LoadOrCreateIdentity(*identityFile, 90*24*time.Hour)
	} else {
		id, err = peer.GenerateIdentity(10 * time.Minute)
	}
	if err != nil {
		die(6, "cannot create identity", err)
	}
	if *certHashFile != "" {
		if err := os.WriteFile(*certHashFile, []byte(id.SHA256+"\n"), 0o600); err != nil {
			die(6, "cannot write cert hash", err)
		}
	}

	conn, br, err := peer.ConnectProxy(addr, *link, *wait)
	if err != nil {
		var re *peer.RefusedError
		if errors.As(err, &re) {
			die(3, "the platform refused the peer link", err)
		}
		die(6, "cannot reach the proxy", err)
	}
	_ = conn.SetDeadline(time.Now().Add(*wait))
	hello, _ := json.Marshal(peer.Hello{V: 1, CertPEM: id.PEM})
	if _, err := conn.Write(append(hello, '\n')); err != nil {
		die(6, "hello failed", err)
	}
	line, err := peer.ReadLine(br)
	if err != nil {
		die(6, "no answer from the relay", err)
	}
	var rep peer.Reply
	if err := json.Unmarshal(line, &rep); err != nil {
		die(6, "malformed relay reply", err)
	}
	if rep.Error != "" {
		die(6, "relay: "+rep.Error, errors.New(rep.Error))
	}
	att, _, err := peer.VerifyAttestation(rep.Attestation, peer.VerifyOptions{
		PlatformKey: pk, LinkID: *link, Own: id, PeerCertPEM: rep.PeerCertPEM, PinPeerSHA256: *pin})
	if err != nil {
		conn.Close()
		die(4, "attestation rejected", err)
	}
	tc := peer.TLS(conn, br, att.Role, id, att.Peer.CertSHA256)
	if err := tc.Handshake(); err != nil {
		conn.Close()
		die(5, "TLS handshake with the peer failed", err)
	}
	_ = conn.SetDeadline(time.Time{})
	emit(map[string]any{"event": "established", "role": att.Role, "link_id": att.LinkID,
		"session_id": att.SessionID, "peer_cell_id": att.Peer.CellID, "peer_tenant_id": att.Peer.TenantID,
		"peer_cert_sha256": att.Peer.CertSHA256, "self_cert_sha256": id.SHA256, "tls": "1.3"})

	var in io.Reader = os.Stdin
	var out io.Writer = os.Stdout
	var local net.Conn
	if ln != nil {
		if local, err = ln.Accept(); err != nil {
			die(6, "accept failed", err)
		}
		ln.Close()
		in, out = local, local
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // local -> peer
		defer wg.Done()
		_, _ = io.Copy(tc, bufio.NewReader(in))
		_ = tc.CloseWrite()
	}()
	go func() { // peer -> local
		defer wg.Done()
		_, _ = io.Copy(out, tc)
		if local != nil {
			if tcp, ok := local.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}
	}()
	wg.Wait()
	_ = tc.Close()
	emit(map[string]any{"event": "closed"})
}
