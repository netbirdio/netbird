package dns

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSelfSignedCert writes a self-signed leaf for 127.0.0.1 and returns its
// file paths and the parsed certificate for use as a trust anchor.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string, leaf *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "netbird-doh-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	leaf, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	return certFile, keyFile, leaf
}

type aHandler struct{ ip net.IP }

func (h aHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 42},
		A:   h.ip,
	})
	_ = w.WriteMsg(resp)
}

func startTestDoH(t *testing.T, handler dns.Handler) (*http.Client, string) {
	t.Helper()

	certFile, keyFile, leaf := writeSelfSignedCert(t)
	cert, err := dohConfig{certFile: certFile, keyFile: keyFile}.loadCertificate()
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := newDoHServer(handler, cert)
	require.NoError(t, srv.start(ln))
	t.Cleanup(srv.stop)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return client, "https://" + ln.Addr().String() + dohPath
}

func packQuery(t *testing.T, name string) []byte {
	t.Helper()

	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	raw, err := q.Pack()
	require.NoError(t, err)
	return raw
}

func readAnswer(t *testing.T, resp *http.Response) *dns.Msg {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	m := new(dns.Msg)
	require.NoError(t, m.Unpack(body), "response body must be a DNS message")
	return m
}

func TestDoHServer_PostAndGet(t *testing.T) {
	client, url := startTestDoH(t, aHandler{ip: net.ParseIP("10.1.2.3")})
	raw := packQuery(t, "svc.example.com.")

	t.Run("POST", func(t *testing.T) {
		resp, err := client.Post(url, dohContentType, bytes.NewReader(raw))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, dohContentType, resp.Header.Get("Content-Type"))
		assert.Equal(t, "max-age=42", resp.Header.Get("Cache-Control"), "freshness must follow the answer TTL")

		m := readAnswer(t, resp)
		require.Len(t, m.Answer, 1, "answer section")
		assert.Equal(t, "10.1.2.3", m.Answer[0].(*dns.A).A.String())
	})

	t.Run("GET", func(t *testing.T) {
		resp, err := client.Get(url + "?dns=" + base64.RawURLEncoding.EncodeToString(raw))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		m := readAnswer(t, resp)
		require.Len(t, m.Answer, 1, "answer section")
		assert.Equal(t, "10.1.2.3", m.Answer[0].(*dns.A).A.String())
	})
}

func TestDoHServer_RejectsBadRequests(t *testing.T) {
	client, url := startTestDoH(t, aHandler{ip: net.ParseIP("10.1.2.3")})
	raw := packQuery(t, "svc.example.com.")

	tests := []struct {
		name   string
		do     func() (*http.Response, error)
		status int
	}{
		{"wrong content type", func() (*http.Response, error) {
			return client.Post(url, "text/plain", bytes.NewReader(raw))
		}, http.StatusUnsupportedMediaType},
		{"garbage body", func() (*http.Response, error) {
			return client.Post(url, dohContentType, bytes.NewReader([]byte("nope")))
		}, http.StatusBadRequest},
		{"GET without dns param", func() (*http.Response, error) {
			return client.Get(url)
		}, http.StatusBadRequest},
		{"GET with padded base64", func() (*http.Response, error) {
			return client.Get(url + "?dns=" + base64.URLEncoding.EncodeToString(raw) + "==")
		}, http.StatusBadRequest},
		{"oversized body", func() (*http.Response, error) {
			return client.Post(url, dohContentType, bytes.NewReader(make([]byte, dns.MaxMsgSize+1)))
		}, http.StatusRequestEntityTooLarge},
		{"unsupported method", func() (*http.Response, error) {
			req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
			require.NoError(t, err)
			return client.Do(req)
		}, http.StatusMethodNotAllowed},
		{"unknown path", func() (*http.Response, error) {
			return client.Post(url+"x", dohContentType, bytes.NewReader(raw))
		}, http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.do()
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, tt.status, resp.StatusCode)
		})
	}
}

func TestDoHServer_RefusesPlainTLS12Downgrade(t *testing.T) {
	_, url := startTestDoH(t, aHandler{ip: net.ParseIP("10.1.2.3")})

	old := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}, //nolint:gosec
		},
	}
	_, err := old.Get(url)
	assert.Error(t, err, "TLS versions below 1.2 must be refused")
}

func TestDoHServer_StopIsIdempotent(t *testing.T) {
	certFile, keyFile, _ := writeSelfSignedCert(t)
	cert, err := dohConfig{certFile: certFile, keyFile: keyFile}.loadCertificate()
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := newDoHServer(aHandler{ip: net.ParseIP("10.1.2.3")}, cert)
	require.NoError(t, srv.start(ln))
	assert.Error(t, srv.start(ln), "second start must be rejected")

	srv.stop()
	srv.stop()

	_, err = net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	assert.Error(t, err, "listener must be closed after stop")
}

func TestDoHConfig(t *testing.T) {
	svcIP := netip.MustParseAddr("100.64.0.5")

	tests := []struct {
		name    string
		listen  string
		want    string
		wantErr bool
	}{
		{"port only binds service address", ":8443", "100.64.0.5:8443", false},
		{"explicit v4", "127.0.0.1:8443", "127.0.0.1:8443", false},
		{"v4-mapped is unmapped", "[::ffff:127.0.0.1]:8443", "127.0.0.1:8443", false},
		{"explicit v6", "[::1]:8443", "[::1]:8443", false},
		{"hostname rejected", "dns.example.com:8443", "", true},
		{"missing port", "127.0.0.1", "", true},
		{"zero port", "127.0.0.1:0", "", true},
		{"port out of range", "127.0.0.1:70000", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dohConfig{listen: tt.listen}.resolveAddr(svcIP)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	_, err := dohConfig{listen: ":8443"}.resolveAddr(netip.Addr{})
	assert.Error(t, err, "port-only needs a service address")

	_, err = dohConfig{}.loadCertificate()
	assert.Error(t, err, "certificate and key are required")

	_, err = dohConfig{certFile: "/nonexistent/cert.pem", keyFile: "/nonexistent/key.pem"}.loadCertificate()
	assert.Error(t, err, "unreadable certificate must fail, not fall back")
}

func newDoHTestServer() *DefaultServer {
	return &DefaultServer{
		handlerChain: NewHandlerChain(),
		service:      &mockService{},
	}
}

func TestDefaultServerStartDoH(t *testing.T) {
	certFile, keyFile, _ := writeSelfSignedCert(t)

	t.Run("disabled without env", func(t *testing.T) {
		t.Setenv(EnvDoHListen, "")
		s := newDoHTestServer()
		s.startDoH()
		assert.Nil(t, s.doh, "listener must stay off when not configured")
	})

	t.Run("does not start without a certificate", func(t *testing.T) {
		t.Setenv(EnvDoHListen, "127.0.0.1:18443")
		t.Setenv(EnvDoHCertFile, "")
		t.Setenv(EnvDoHKeyFile, "")
		s := newDoHTestServer()
		s.startDoH()
		assert.Nil(t, s.doh, "missing certificate must not fall back to plain HTTP")
	})

	t.Run("starts and stops", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close())

		t.Setenv(EnvDoHListen, addr)
		t.Setenv(EnvDoHCertFile, certFile)
		t.Setenv(EnvDoHKeyFile, keyFile)

		s := newDoHTestServer()
		s.startDoH()
		require.NotNil(t, s.doh, "listener must start when configured")

		s.startDoH()
		s.stopDoH()
		s.stopDoH()
		assert.Nil(t, s.doh)
	})
}
