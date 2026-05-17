//go:build devcert

package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// devCertHash holds the SHA-256 hash of the latest generated dev certificate.
// The WASM WebTransport client reads it via DevCertHash() to pin the self-
// signed cert through serverCertificateHashes — browsers require an ECDSA cert
// with validity <= 14 days when this pinning mode is used.
var (
	devCertHashMu sync.RWMutex
	devCertHash   []byte
)

// DevCertHash returns the SHA-256 hash of the dev TLS certificate, or nil if
// no dev cert has been generated yet. WASM clients can pass this through
// serverCertificateHashes on WebTransport handshake.
func DevCertHash() []byte {
	devCertHashMu.RLock()
	defer devCertHashMu.RUnlock()
	if devCertHash == nil {
		return nil
	}
	out := make([]byte, len(devCertHash))
	copy(out, devCertHash)
	return out
}

func setDevCertHash(certDER []byte) {
	sum := sha256.Sum256(certDER)
	devCertHashMu.Lock()
	devCertHash = sum[:]
	devCertHashMu.Unlock()
}

func ServerQUICTLSConfig(originTLSCfg *tls.Config) (*tls.Config, error) {
	if originTLSCfg == nil {
		log.Warnf("QUIC server will use self signed certificate for testing!")
		return generateTestTLSConfig([]string{NBalpn})
	}

	cfg := originTLSCfg.Clone()
	cfg.NextProtos = []string{NBalpn}
	return cfg, nil
}

// ServerMuxTLSConfig returns a TLS config offering both ALPNs so a single UDP
// socket can serve raw QUIC and WebTransport clients.
func ServerMuxTLSConfig(originTLSCfg *tls.Config) (*tls.Config, error) {
	if originTLSCfg == nil {
		log.Warnf("QUIC/WT server will use self signed certificate for testing!")
		return generateTestTLSConfig([]string{NBalpn, H3alpn})
	}

	cfg := originTLSCfg.Clone()
	cfg.NextProtos = []string{NBalpn, H3alpn}
	return cfg, nil
}

// generateTestTLSConfig creates a self-signed ECDSA P-256 certificate suitable
// for both raw QUIC and browser WebTransport. Validity is capped at 13 days so
// the cert remains usable with WebTransport serverCertificateHashes pinning
// (browser limit is 14 days).
func generateTestTLSConfig(alpns []string) (*tls.Config, error) {
	log.Infof("generating test TLS config (ECDSA P-256, 13 day validity) for ALPNs %v", alpns)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 13),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	setDevCertHash(certDER)

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   alpns,
	}, nil
}
