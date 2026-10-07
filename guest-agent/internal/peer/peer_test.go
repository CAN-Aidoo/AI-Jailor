package peer

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	a, b    *Identity
	link    string
	attForA json.RawMessage
}

func sign(priv ed25519.PrivateKey, pred map[string]any, ptype string) json.RawMessage {
	st, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": ptype, "predicate": pred})
	sig := ed25519.Sign(priv, pae(PayloadType, st))
	env, _ := json.Marshal(map[string]any{
		"payloadType": PayloadType, "payload": base64.StdEncoding.EncodeToString(st),
		"signatures": []map[string]string{{"keyid": "k", "sig": base64.StdEncoding.EncodeToString(sig)}}})
	return env
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := GenerateIdentity(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateIdentity(10 * time.Minute)
	f := &fixture{pub: pub, priv: priv, a: a, b: b, link: strings.Repeat("a", 32)}
	f.attForA = f.att(f.priv, f.link, "initiator", f.a.SHA256, f.b.SHA256, PredicateType, float64(time.Now().Unix()), 600)
	return f
}

func (f *fixture) att(priv ed25519.PrivateKey, link, role, self, peer, ptype string, issued float64, ttl float64) json.RawMessage {
	return sign(priv, map[string]any{
		"link_id": link, "role": role, "session_id": "s",
		"self":      map[string]string{"cell_id": "cell-a", "tenant_id": "t-a", "cert_sha256": self},
		"peer":      map[string]string{"cell_id": "cell-b", "tenant_id": "t-b", "cert_sha256": peer},
		"issued_at": issued, "expires_at": issued + ttl}, ptype)
}

func (f *fixture) opts() VerifyOptions {
	return VerifyOptions{PlatformKey: f.pub, LinkID: f.link, Own: f.a, PeerCertPEM: f.b.PEM}
}

func TestIdentityIsAnEphemeralSelfSignedCAWithAMatchingHash(t *testing.T) {
	id, err := GenerateIdentity(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h, der, err := CertSHA256(id.PEM)
	if err != nil || h != id.SHA256 {
		t.Fatalf("hash mismatch %v %s %s", err, h, id.SHA256)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil || !c.IsCA || c.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("unexpected certificate: %v", err)
	}
	if time.Until(c.NotAfter) > 11*time.Minute || time.Since(c.NotBefore) > 2*time.Minute {
		t.Fatalf("validity window wrong: %v..%v", c.NotBefore, c.NotAfter)
	}
	other, _ := GenerateIdentity(time.Minute)
	if other.SHA256 == id.SHA256 {
		t.Fatal("two identities share a hash")
	}
}

func TestPersistentIdentityKeepsItsHashAndIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.pem")
	one, err := LoadOrCreateIdentity(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	two, err := LoadOrCreateIdentity(path, time.Hour)
	if err != nil || one.SHA256 != two.SHA256 {
		t.Fatalf("hash changed across loads: %v", err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("identity file mode %v", st.Mode().Perm())
	}
	os.WriteFile(path, []byte("garbage"), 0o600)
	if _, err := LoadOrCreateIdentity(path, time.Hour); err == nil {
		t.Fatal("a corrupt identity file must be an error, not silently replaced")
	}
}

func TestVerifyAcceptsTheGenuineAttestation(t *testing.T) {
	f := newFixture(t)
	o := f.opts()
	o.ExpectRole, o.PinPeerSHA256 = "initiator", strings.ToUpper(f.b.SHA256)
	a, _, err := VerifyAttestation(f.attForA, o)
	if err != nil || a.Peer.CellID != "cell-b" || a.Role != "initiator" {
		t.Fatalf("genuine attestation rejected: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFixture(t)
	evil, _ := GenerateIdentity(time.Minute)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := float64(time.Now().Unix())
	cases := map[string]func(o *VerifyOptions, att *json.RawMessage){
		"wrong platform key": func(o *VerifyOptions, _ *json.RawMessage) { o.PlatformKey = otherPub },
		"signed by someone else": func(_ *VerifyOptions, a *json.RawMessage) {
			*a = f.att(otherPriv, f.link, "initiator", f.a.SHA256, f.b.SHA256, PredicateType, now, 600)
		},
		"other link":    func(o *VerifyOptions, _ *json.RawMessage) { o.LinkID = strings.Repeat("b", 32) },
		"not our cert":  func(o *VerifyOptions, _ *json.RawMessage) { o.Own = evil },
		"swapped peer":  func(o *VerifyOptions, _ *json.RawMessage) { o.PeerCertPEM = evil.PEM },
		"wrong pin":     func(o *VerifyOptions, _ *json.RawMessage) { o.PinPeerSHA256 = evil.SHA256 },
		"wrong role":    func(o *VerifyOptions, _ *json.RawMessage) { o.ExpectRole = "responder" },
		"expired":       func(o *VerifyOptions, _ *json.RawMessage) { o.Now = time.Now().Add(time.Hour) },
		"not yet valid": func(o *VerifyOptions, _ *json.RawMessage) { o.Now = time.Now().Add(-time.Hour) },
		"wrong predicate type": func(_ *VerifyOptions, a *json.RawMessage) {
			*a = f.att(f.priv, f.link, "initiator", f.a.SHA256, f.b.SHA256, "https://evil/v1", now, 600)
		},
		"bad role value": func(_ *VerifyOptions, a *json.RawMessage) {
			*a = f.att(f.priv, f.link, "admin", f.a.SHA256, f.b.SHA256, PredicateType, now, 600)
		},
		"tampered payload": func(_ *VerifyOptions, a *json.RawMessage) {
			var env map[string]any
			json.Unmarshal(*a, &env)
			p := env["payload"].(string)
			env["payload"] = p[:len(p)-4] + "AAAA"
			*a, _ = json.Marshal(env)
		},
		"garbage envelope":   func(_ *VerifyOptions, a *json.RawMessage) { *a = json.RawMessage(`{"payloadType":1}`) },
		"short platform key": func(o *VerifyOptions, _ *json.RawMessage) { o.PlatformKey = otherPub[:5] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o, att := f.opts(), f.attForA
			mutate(&o, &att)
			if _, _, err := VerifyAttestation(att, o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// tcpPair returns two connected ends over loopback.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c1, <-ch
}

func TestMutualTLSBetweenTheAttestedPeers(t *testing.T) {
	f := newFixture(t)
	ci, cr := tcpPair(t)
	defer ci.Close()
	defer cr.Close()
	ti := TLS(ci, bufio.NewReader(ci), "initiator", f.a, f.b.SHA256)
	tr := TLS(cr, bufio.NewReader(cr), "responder", f.b, f.a.SHA256)
	errs := make(chan error, 2)
	go func() { errs <- ti.Handshake() }()
	go func() { errs <- tr.Handshake() }()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	if ti.ConnectionState().Version != 0x0304 {
		t.Fatalf("not TLS 1.3: %x", ti.ConnectionState().Version)
	}
	go ti.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tr, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("data: %v %q", err, buf)
	}
}

func TestTLSFailsWhenEitherSideSeesTheWrongCertificate(t *testing.T) {
	f := newFixture(t)
	evil, _ := GenerateIdentity(time.Minute)
	for name, hashes := range map[string][2]string{
		"initiator expects wrong": {evil.SHA256, f.a.SHA256},
		"responder expects wrong": {f.b.SHA256, evil.SHA256},
	} {
		t.Run(name, func(t *testing.T) {
			ci, cr := tcpPair(t)
			defer ci.Close()
			defer cr.Close()
			ti := TLS(ci, bufio.NewReader(ci), "initiator", f.a, hashes[0])
			tr := TLS(cr, bufio.NewReader(cr), "responder", f.b, hashes[1])
			ci.SetDeadline(time.Now().Add(5 * time.Second))
			cr.SetDeadline(time.Now().Add(5 * time.Second))
			errs := make(chan error, 2)
			go func() { errs <- ti.Handshake() }()
			go func() { errs <- tr.Handshake() }()
			failed := 0
			for i := 0; i < 2; i++ {
				if <-errs != nil {
					failed++
				}
			}
			if failed == 0 {
				t.Fatal("handshake succeeded with an unattested certificate")
			}
		})
	}
}

func TestResponderRefusesAClientThatPresentsNoCertificate(t *testing.T) {
	f := newFixture(t)
	ci, cr := tcpPair(t)
	defer ci.Close()
	defer cr.Close()
	tr := TLS(cr, bufio.NewReader(cr), "responder", f.b, f.a.SHA256)
	go func() { _ = tlsClientNoCert(ci, f.b.SHA256).Handshake() }()
	cr.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tr.Handshake(); err == nil {
		t.Fatal("responder accepted a client with no certificate")
	}
}

func TestTLSIsFedTheBytesTheLineReaderAlreadyBuffered(t *testing.T) {
	// The initiator's first TLS record can arrive in the SAME segment as the attestation line. The
	// responder reads the line with a buffered reader; those extra bytes must reach TLS, not vanish.
	f := newFixture(t)
	ci, cr := tcpPair(t)
	defer ci.Close()
	defer cr.Close()
	ti := TLS(ci, bufio.NewReader(ci), "initiator", f.a, f.b.SHA256)
	go func() {
		ci.Write([]byte("{\"line\":1}\n"))
		_ = ti.Handshake() // sends its ClientHello right behind the line
	}()
	time.Sleep(300 * time.Millisecond) // let both arrive and be buffered together
	br := bufio.NewReaderSize(cr, 64*1024)
	if _, err := ReadLine(br); err != nil {
		t.Fatal(err)
	}
	if br.Buffered() == 0 {
		t.Skip("kernel delivered the line and the ClientHello separately; nothing to prove here")
	}
	tr := TLS(cr, br, "responder", f.b, f.a.SHA256)
	cr.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tr.Handshake(); err != nil {
		t.Fatalf("buffered ClientHello was lost: %v", err)
	}
}

func TestReadLineEnforcesALimit(t *testing.T) {
	huge := strings.NewReader(strings.Repeat("x", maxLine+10) + "\n")
	if _, err := ReadLine(bufio.NewReaderSize(huge, 4096)); err == nil {
		t.Fatal("unbounded line accepted")
	}
}

// tlsClientNoCert is a TLS 1.3 client that trusts the responder but presents NO client certificate.
func tlsClientNoCert(conn net.Conn, serverHash string) *tlsConnShim {
	return newNoCertClient(conn, serverHash)
}
