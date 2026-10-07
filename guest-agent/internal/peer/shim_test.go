package peer

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
)

type tlsConnShim struct{ *tls.Conn }

func newNoCertClient(conn net.Conn, serverHash string) *tlsConnShim {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, ServerName: ServerName,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			s := sha256.Sum256(raw[0])
			if hex.EncodeToString(s[:]) != serverHash {
				return errors.New("wrong server")
			}
			return nil
		}}
	return &tlsConnShim{tls.Client(conn, cfg)}
}
