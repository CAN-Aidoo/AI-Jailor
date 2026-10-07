// Package peer is the cell-side half of an attested peer link: it makes an ephemeral certificate,
// verifies the platform's attestation of the PEER's certificate, and runs mutual TLS 1.3 over the
// relayed byte stream trusting only that attested certificate. Standard library crypto only.
package peer

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	PayloadType   = "application/vnd.in-toto+json"
	PredicateType = "https://aijailer.dev/attestation/peer-link/v1"
	ClockSkew     = 5 * time.Minute
	maxLine       = 1 << 20
	// ServerName is only a label for the TLS client: identity is the attested certificate, not a name.
	ServerName = "peer.aijailer.invalid"
)

// Identity is this cell's ephemeral certificate. The private key never leaves the process.
type Identity struct {
	Cert   tls.Certificate
	PEM    string
	SHA256 string // hex sha256 of the DER certificate
}

func GenerateIdentity(validFor time.Duration) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "aijailer-peer"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed: it is its own trust anchor for the peer
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &Identity{
		Cert:   tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		SHA256: hex.EncodeToString(sum[:]),
	}, nil
}

// LoadOrCreateIdentity returns the identity stored at path (certificate + key, mode 0600), creating
// it on first use. A persistent identity has a STABLE certificate hash, which is what makes an
// out-of-band pin (--pin on the other side) possible: share the hash once, outside the platform.
func LoadOrCreateIdentity(path string, validFor time.Duration) (*Identity, error) {
	if data, err := os.ReadFile(path); err == nil {
		cert, err := tls.X509KeyPair(data, data)
		if err != nil {
			return nil, fmt.Errorf("identity file %s: %w", path, err)
		}
		if len(cert.Certificate) == 0 {
			return nil, errors.New("identity file has no certificate")
		}
		sum := sha256.Sum256(cert.Certificate[0])
		return &Identity{Cert: cert, SHA256: hex.EncodeToString(sum[:]),
			PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))}, nil
	}
	id, err := GenerateIdentity(validFor)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(id.Cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	blob := id.PEM + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err := os.WriteFile(path, []byte(blob), 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

// CertSHA256 returns the hex sha256 of the DER encoding of a PEM certificate.
func CertSHA256(certPEM string) (string, []byte, error) {
	if len(certPEM) > 8*1024 {
		return "", nil, errors.New("certificate too large")
	}
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", nil, errors.New("not a PEM certificate")
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:]), blk.Bytes, nil
}

type party struct {
	CellID     string `json:"cell_id"`
	TenantID   string `json:"tenant_id"`
	CertSHA256 string `json:"cert_sha256"`
}

// Attested is what a verified attestation tells this cell.
type Attested struct {
	LinkID    string  `json:"link_id"`
	Role      string  `json:"role"`
	SessionID string  `json:"session_id"`
	Self      party   `json:"self"`
	Peer      party   `json:"peer"`
	IssuedAt  float64 `json:"issued_at"`
	ExpiresAt float64 `json:"expires_at"`
}

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type statement struct {
	PredicateType string   `json:"predicateType"`
	Predicate     Attested `json:"predicate"`
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

type VerifyOptions struct {
	PlatformKey   ed25519.PublicKey
	LinkID        string
	Own           *Identity
	PeerCertPEM   string
	ExpectRole    string // optional
	PinPeerSHA256 string // optional, hex: out-of-band pin on the peer's certificate
	Now           time.Time
}

// VerifyAttestation is everything a cell must check before trusting the peer's certificate.
func VerifyAttestation(raw json.RawMessage, o VerifyOptions) (*Attested, []byte, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.PayloadType != PayloadType {
		return nil, nil, errors.New("malformed attestation envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, errors.New("malformed attestation payload")
	}
	msg := pae(env.PayloadType, payload)
	okSig := false
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err == nil && len(o.PlatformKey) == ed25519.PublicKeySize && ed25519.Verify(o.PlatformKey, msg, sig) {
			okSig = true
			break
		}
	}
	if !okSig {
		return nil, nil, errors.New("attestation signature invalid (wrong platform key?)")
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil || st.PredicateType != PredicateType {
		return nil, nil, errors.New("attestation type invalid")
	}
	a := st.Predicate
	if a.LinkID != o.LinkID {
		return nil, nil, errors.New("attestation is for a different link")
	}
	if a.Role != "initiator" && a.Role != "responder" {
		return nil, nil, errors.New("unexpected role")
	}
	if o.ExpectRole != "" && a.Role != o.ExpectRole {
		return nil, nil, errors.New("unexpected role")
	}
	if a.Self.CertSHA256 != o.Own.SHA256 {
		return nil, nil, errors.New("attestation does not name our certificate")
	}
	peerHash, peerDER, err := CertSHA256(o.PeerCertPEM)
	if err != nil {
		return nil, nil, err
	}
	if a.Peer.CertSHA256 != peerHash {
		return nil, nil, errors.New("peer certificate does not match the attested hash")
	}
	if o.PinPeerSHA256 != "" && !strings.EqualFold(o.PinPeerSHA256, peerHash) {
		return nil, nil, errors.New("peer certificate does not match the pinned hash")
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	ts := float64(now.UnixNano()) / 1e9
	if ts < a.IssuedAt-ClockSkew.Seconds() || ts > a.ExpiresAt+ClockSkew.Seconds() {
		return nil, nil, errors.New("attestation expired or not yet valid")
	}
	return &a, peerDER, nil
}

// bufConn feeds bytes the line reader already buffered to the TLS layer first: the peer's first
// TLS records may arrive in the same segment as the attestation line.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// TLS wraps the relayed connection in mutual TLS 1.3 whose only trust anchor is the attested peer
// certificate (compared by hash, so no CA logic is involved on either side).
func TLS(conn net.Conn, br *bufio.Reader, role string, own *Identity, peerHashHex string) *tls.Conn {
	verify := func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("peer presented no certificate")
		}
		sum := sha256.Sum256(raw[0])
		if hex.EncodeToString(sum[:]) != peerHashHex {
			return errors.New("peer certificate is not the attested one")
		}
		return nil
	}
	cfg := &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{own.Cert},
		InsecureSkipVerify:    true, // chain/name checks replaced by the pin below: identity is the cert hash
		VerifyPeerCertificate: verify,
		ClientAuth:            tls.RequireAnyClientCert, // mutual: the responder demands the initiator's cert
		ServerName:            ServerName,
	}
	bc := &bufConn{Conn: conn, r: io.MultiReader(br, conn)}
	if role == "initiator" {
		return tls.Client(bc, cfg)
	}
	return tls.Server(bc, cfg)
}

// ReadLine reads one newline-terminated line without ever reading past it from the connection
// beyond what the bufio.Reader buffers (the caller hands that buffer to TLS()).
func ReadLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > maxLine {
			return nil, errors.New("line too long")
		}
		if !isPrefix {
			return line, nil
		}
	}
}

// Hello is what we send; Reply is what the hub answers once the peer is present.
type Hello struct {
	V       int    `json:"v"`
	CertPEM string `json:"cert_pem"`
}

type Reply struct {
	V           int             `json:"v"`
	Error       string          `json:"error,omitempty"`
	Attestation json.RawMessage `json:"attestation,omitempty"`
	PeerCertPEM string          `json:"peer_cert_pem,omitempty"`
	SessionID   string          `json:"session_id,omitempty"`
}

// ConnectProxy opens CONNECT <link>.peer.aijailer.invalid:443 through the cell's proxy and returns the
// connection plus the buffered reader that MUST be used for everything that follows.
func ConnectProxy(proxyAddr, linkID string, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	host := linkID + ".peer.aijailer.invalid:443"
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReaderSize(conn, 64*1024)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	fields := strings.Fields(status)
	code, _ := strconv.Atoi(func() string {
		if len(fields) > 1 {
			return fields[1]
		}
		return "0"
	}())
	var body []byte
	for { // headers
		l, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if code != 200 {
		body, _ = io.ReadAll(io.LimitReader(br, 4096))
		conn.Close()
		return nil, nil, &RefusedError{Status: code, Body: strings.TrimSpace(string(body))}
	}
	return conn, br, nil
}

// RefusedError: the proxy said no (link unknown/inactive, not a party, peer links disabled...).
type RefusedError struct {
	Status int
	Body   string
}

func (e *RefusedError) Error() string { return fmt.Sprintf("proxy refused (%d): %s", e.Status, e.Body) }
