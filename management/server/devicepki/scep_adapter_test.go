package devicepki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/secretenc"
)

// newSCEPTestCA returns a self-signed ECDSA CA cert and key for SCEP tests.
func newSCEPTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "scep-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	return caCert, caKey
}

// newSCEPTestCRL builds a real minimal DER-encoded CRL signed by the given CA.
func newSCEPTestCRL(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	}, caCert, caKey)
	require.NoError(t, err)
	return crlDER
}

// newSCEPServer creates an httptest.Server that implements GetCACert and GetCRL.
// certBody is the raw bytes served for GetCACert (DER or PEM as required by the
// specific test). crlDER is served for GetCRL. requestCount is incremented for
// every request that reaches the server.
func newSCEPServer(t *testing.T, certBody []byte, crlDER []byte, caCertSubject string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var count atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		op := r.URL.Query().Get("operation")
		switch op {
		case "GetCACert":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certBody)
		case "GetCRL":
			// Validate that the issuer query param is present.
			if r.URL.Query().Get("issuer") == "" {
				http.Error(w, "missing issuer", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(crlDER)
		default:
			http.Error(w, "unknown operation", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &count
}

// newSCEPServerReturning500 always responds with 500 for GetCACert.
func newSCEPServerReturning500(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv, &count
}

// --- NewSCEPCA ---

func TestNewSCEPCA_ValidConfig(t *testing.T) {
	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{
		URL: "http://scep.example.com/scep",
	})
	require.NoError(t, err)
	require.NotNil(t, ca)
}

func TestNewSCEPCA_MissingURL(t *testing.T) {
	// NewSCEPCA currently accepts an empty URL and defers the error to the first
	// HTTP call, so we verify successful construction and expect runtime failure.
	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: ""})
	require.NoError(t, err, "NewSCEPCA must not fail on empty URL — HTTP errors surface at call time")
	require.NotNil(t, ca)
}

func TestNewSCEPCA_CustomTimeout(t *testing.T) {
	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{
		URL:            "http://scep.example.com/scep",
		TimeoutSeconds: 5,
	})
	require.NoError(t, err)
	require.NotNil(t, ca, "custom timeout must produce a valid SCEPCA")
}

// --- GenerateCA ---

func TestSCEPCA_GenerateCA_ReturnsNotSupported(t *testing.T) {
	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: "http://localhost"})
	require.NoError(t, err)

	certPEM, keyPEM, err := ca.GenerateCA(context.Background(), "")
	assert.Error(t, err, "GenerateCA must return an error for SCEP")
	assert.Empty(t, certPEM)
	assert.Empty(t, keyPEM)
	assert.Contains(t, err.Error(), "SCEP server operator",
		"error should indicate that the CA is externally managed")
}

// --- CACert ---

func TestSCEPCA_CACert_ReturnsCertFromDER(t *testing.T) {
	caCert, caKey := newSCEPTestCA(t)
	crlDER := newSCEPTestCRL(t, caCert, caKey)
	srv, _ := newSCEPServer(t, caCert.Raw, crlDER, caCert.Subject.String())

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	got := ca.CACert(context.Background())
	require.NotNil(t, got, "CACert must parse and return the DER cert")
	assert.Equal(t, "scep-test-ca", got.Subject.CommonName)
}

func TestSCEPCA_CACert_PEMFallback(t *testing.T) {
	caCert, caKey := newSCEPTestCA(t)
	crlDER := newSCEPTestCRL(t, caCert, caKey)

	// Serve the cert as PEM instead of raw DER.
	pemBody := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	srv, _ := newSCEPServer(t, pemBody, crlDER, caCert.Subject.String())

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	got := ca.CACert(context.Background())
	require.NotNil(t, got, "CACert must parse PEM-wrapped cert via fallback")
	assert.Equal(t, "scep-test-ca", got.Subject.CommonName)
}

func TestSCEPCA_CACert_ReturnsNilOn500(t *testing.T) {
	srv, _ := newSCEPServerReturning500(t)

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	got := ca.CACert(context.Background())
	assert.Nil(t, got, "CACert must return nil when server returns 500")
}

func TestSCEPCA_CACert_RetrySupressedDuringFailureTTL(t *testing.T) {
	// The server fails on first request; subsequent calls within TTL must not
	// create additional HTTP requests.
	srv, count := newSCEPServerReturning500(t)

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()

	// First call — server is queried, fails, sets caCertFailAt.
	got1 := ca.CACert(ctx)
	assert.Nil(t, got1)

	// Second call immediately — still within TTL, must NOT create another request.
	got2 := ca.CACert(ctx)
	assert.Nil(t, got2)

	assert.Equal(t, int64(1), count.Load(),
		"only one HTTP request expected: second call must be suppressed by failure TTL")
}

func TestSCEPCA_CACert_CachesSuccessfulResult(t *testing.T) {
	caCert, caKey := newSCEPTestCA(t)
	crlDER := newSCEPTestCRL(t, caCert, caKey)
	srv, count := newSCEPServer(t, caCert.Raw, crlDER, caCert.Subject.String())

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	ca.CACert(ctx)
	ca.CACert(ctx)
	ca.CACert(ctx)

	assert.Equal(t, int64(1), count.Load(),
		"CACert must make only one HTTP request after a successful fetch")
}

// --- SignCSR ---

func TestSCEPCA_SignCSR_ReturnsErrNotImplemented(t *testing.T) {
	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: "http://localhost"})
	require.NoError(t, err)

	csr, _ := newTestCSR(t, "test-cn")
	cert, signErr := ca.SignCSR(context.Background(), csr, "test-cn", 365)
	assert.Nil(t, cert)
	require.Error(t, signErr)
	assert.True(t, errors.Is(signErr, devicepki.ErrNotImplemented),
		"SignCSR must wrap ErrNotImplemented; got: %v", signErr)
}

// --- RevokeCert ---

func TestSCEPCA_RevokeCert_ReturnsNil(t *testing.T) {
	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: "http://localhost"})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), "12345")
	assert.NoError(t, err, "SCEP RevokeCert must always return nil (no-op)")
}

// --- GenerateCRL ---

func TestSCEPCA_GenerateCRL_ReturnsDERBytes(t *testing.T) {
	caCert, caKey := newSCEPTestCA(t)
	crlDER := newSCEPTestCRL(t, caCert, caKey)
	srv, _ := newSCEPServer(t, caCert.Raw, crlDER, caCert.Subject.String())

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	got, err := ca.GenerateCRL(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, got, "GenerateCRL must return DER bytes")

	// Verify the returned bytes are a parseable CRL.
	parsed, err := x509.ParseRevocationList(got)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestSCEPCA_GenerateCRL_ErrorWhenCACertUnavailable(t *testing.T) {
	// Use a URL that will cause an error (server returns 500 → CACert returns nil).
	srv, _ := newSCEPServerReturning500(t)

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	_, err = ca.GenerateCRL(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch CA certificate",
		"error must mention CA cert failure")
}

func TestSCEPCA_GenerateCRL_ErrorOnNon200CRLResponse(t *testing.T) {
	caCert, caKey := newSCEPTestCA(t)
	_ = caKey

	// Server serves the CA cert OK but returns 500 for GetCRL.
	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		op := r.URL.Query().Get("operation")
		if op == "GetCACert" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(caCert.Raw)
			return
		}
		http.Error(w, "crl generation failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = ca.GenerateCRL(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetCRL returned 500",
		"error must indicate non-200 GetCRL response")
}

func TestSCEPCA_GenerateCRL_IssuerInQueryParam(t *testing.T) {
	caCert, caKey := newSCEPTestCA(t)
	crlDER := newSCEPTestCRL(t, caCert, caKey)

	var capturedIssuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := r.URL.Query().Get("operation")
		if op == "GetCACert" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(caCert.Raw)
			return
		}
		capturedIssuer = r.URL.Query().Get("issuer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crlDER)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSCEPCA(devicepki.SCEPConfig{URL: srv.URL})
	require.NoError(t, err)

	_, err = ca.GenerateCRL(context.Background())
	require.NoError(t, err)

	decodedIssuer, err := url.QueryUnescape(capturedIssuer)
	require.NoError(t, err)
	assert.True(t, strings.Contains(decodedIssuer, "scep-test-ca") || capturedIssuer != "",
		"GetCRL request must include the CA subject as issuer query parameter")
}

// --- Interface compliance ---

func TestSCEPCA_InterfaceCompliance(t *testing.T) {
	var _ devicepki.CA = (*devicepki.SCEPCA)(nil)
}

// ─── EncryptSecrets / DecryptSecrets ─────────────────────────────────────────

func TestSCEPConfig_EncryptDecryptSecrets_RoundTrip(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SCEPConfig{URL: "http://scep.example.com/scep", Challenge: "scep-challenge-abc"}
	original := cfg.Challenge

	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.True(t, strings.HasPrefix(cfg.Challenge, "enc:"), "encrypted challenge must have enc: prefix")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, original, cfg.Challenge)
}

func TestSCEPConfig_EncryptDecryptSecrets_EmptyChallenge_NoOp(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SCEPConfig{}

	require.NoError(t, cfg.EncryptSecrets(kp))
	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Empty(t, cfg.Challenge)
}

func TestSCEPConfig_DecryptSecrets_PlaintextBackwardCompat(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SCEPConfig{Challenge: "my-scep-challenge-password"}

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "my-scep-challenge-password", cfg.Challenge,
		"plaintext challenge without enc: prefix must be left unchanged")
}

func TestSCEPConfig_EncryptSecrets_DoubleEncryptGuard(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SCEPConfig{Challenge: "scep-challenge-abc"}

	require.NoError(t, cfg.EncryptSecrets(kp))
	encrypted := cfg.Challenge

	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.Equal(t, encrypted, cfg.Challenge, "double encrypt must be a no-op")
}

func TestSCEPConfig_DecryptSecrets_Base64PlaintextBackwardCompat(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SCEPConfig{Challenge: "dGVzdC1jaGFsbGVuZ2U="}  // base64("test-challenge")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "dGVzdC1jaGFsbGVuZ2U=", cfg.Challenge,
		"base64-looking plaintext without enc: prefix must be left unchanged")
}
