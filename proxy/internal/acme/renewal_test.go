package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// These tests start from a certificate cached in the cert dir and already
// inside its renewal window. They run the real handshake path (a TLS
// listener configured like server.go) against a fake ACME CA that rejects
// every order, the way a failing tls-alpn-01 validation does.

const renewalTestDomain = "renewal.example.test"

// fakeCA is the smallest RFC 8555 server autocert will talk to: discovery,
// nonces and account registration succeed, every new order is rejected.
type fakeCA struct {
	srv    *httptest.Server
	orders atomic.Int32
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	ca := &fakeCA{}
	mux := http.NewServeMux()
	base := func() string { return ca.srv.URL }
	nonce := func(w http.ResponseWriter) { w.Header().Set("Replay-Nonce", time.Now().Format(time.RFC3339Nano)) }

	mux.HandleFunc("/dir", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   base() + "/nonce",
			"newAccount": base() + "/account",
			"newOrder":   base() + "/order",
			"revokeCert": base() + "/revoke",
			"keyChange":  base() + "/key-change",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		w.Header().Set("Location", base()+"/account/1")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"valid"}`))
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, _ *http.Request) {
		ca.orders.Add(1)
		nonce(w)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:unauthorized","detail":"fake CA: tls-alpn-01 validation failed"}`))
	})

	ca.srv = httptest.NewTLSServer(mux)
	t.Cleanup(ca.srv.Close)
	return ca
}

// syncBuffer collects the manager's log output; renewal runs on its own
// goroutine, so writes and reads race without the lock.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// writeCachedCert puts a certificate for name in the autocert cache the way
// a previous issuance would have: issued 80 days ago with `left` remaining,
// so autocert's renewal window has opened.
// It returns the pool that trusts it.
func writeCachedCert(t *testing.T, certDir, name string, left time.Duration) *x509.CertPool {
	t.Helper()
	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake issuer"},
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-80 * 24 * time.Hour),
		NotAfter:     now.Add(left),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	var data bytes.Buffer
	require.NoError(t, pem.Encode(&data, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, pem.Encode(&data, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	require.NoError(t, pem.Encode(&data, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	// autocert.DirCache keys ECDSA certificates by the bare domain.
	require.NoError(t, os.WriteFile(filepath.Join(certDir, name), data.Bytes(), 0o600))

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool
}

// startRenewalProxy builds a manager on a cert dir holding a cached
// certificate in its renewal window, pointed at a fake CA, and serves its
// TLS config on a loopback listener exactly as server.go configures it.
func startRenewalProxy(t *testing.T, left time.Duration) (mgr *Manager, ca *fakeCA, roots *x509.CertPool, addr string, logs *syncBuffer) {
	t.Helper()
	certDir := t.TempDir()
	roots = writeCachedCert(t, certDir, renewalTestDomain, left)
	ca = newFakeCA(t)

	logs = &syncBuffer{}
	logger := log.New()
	logger.SetOutput(logs)
	logger.SetLevel(log.DebugLevel)

	mgr, err := NewManager(ManagerConfig{CertDir: certDir, ACMEURL: ca.srv.URL + "/dir"}, nil, logger, nil)
	require.NoError(t, err)
	mgr.Manager.Client.HTTPClient = ca.srv.Client()

	// server.go: tlsConfig = s.acme.TLSConfig(); tlsConfig.GetCertificate = s.acme.GetCertificate
	tlsConfig := mgr.TLSConfig()
	tlsConfig.GetCertificate = mgr.GetCertificate

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()

	mgr.AddDomain(domain.Domain(renewalTestDomain), types.AccountID("acc"), types.ServiceID("svc"))
	require.Eventually(t, func() bool {
		return len(mgr.ReadyDomains()) == 1
	}, 5*time.Second, 20*time.Millisecond, "prefetch should take the cached certificate")
	require.Contains(t, logs.String(), "already on disk, skipping ACME")

	return mgr, ca, roots, ln.Addr().String(), logs
}

// handshake connects as a client for the domain and returns the certificate
// the proxy served.
func handshake(t *testing.T, addr string, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: renewalTestDomain, RootCAs: roots})
	require.NoError(t, err)
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

// A certificate taken from disk by the prefetch is renewed without waiting for
// a client to connect.
func TestRenewal_CachedCertWithoutTrafficIsRenewed(t *testing.T) {
	_, ca, _, _, _ := startRenewalProxy(t, 10*24*time.Hour)

	// autocert would renew at once: the window opened 20 days ago.
	assert.Eventually(t, func() bool { return ca.orders.Load() > 0 }, 3*time.Second, 50*time.Millisecond,
		"no renewal was attempted for a cached certificate 10 days from expiry while the domain saw no TLS traffic")
}

// A renewal that keeps failing is reported once it is overdue, and the
// domain is marked failed once the certificate has expired.
func TestRenewal_FailureIsReported(t *testing.T) {
	mgr, ca, roots, addr, logs := startRenewalProxy(t, 10*24*time.Hour)

	served := handshake(t, addr, roots)
	assert.Equal(t, int64(2), served.SerialNumber.Int64(), "the cached certificate is served")
	require.Eventually(t, func() bool { return ca.orders.Load() > 0 }, 5*time.Second, 50*time.Millisecond,
		"renewal should have been attempted")

	// The cached cert's renewal point passed 20 days ago.
	mgr.checkExpiry(context.Background(), time.Now())
	assert.Contains(t, logs.String(), "level=warning", "an overdue renewal of %q must be logged", renewalTestDomain)
	assert.Contains(t, logs.String(), "has not succeeded")
	assert.Contains(t, mgr.ReadyDomains(), renewalTestDomain, "a still-valid certificate keeps the domain ready")

	mgr.checkExpiry(context.Background(), time.Now().Add(11*24*time.Hour))
	assert.Contains(t, logs.String(), "level=error", "an expired certificate of %q must be logged", renewalTestDomain)
	assert.Contains(t, mgr.FailedDomains(), renewalTestDomain, "an expired certificate must mark the domain failed")
}
