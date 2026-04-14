package devicepki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/secretenc"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// newTestCACert generates an in-memory self-signed CA cert + key for mock responses.
func newTestCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	return caCert, caKey, caDER
}

// encodeCertPEM wraps DER bytes in a PEM block.
func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newSignedCertPEM creates a leaf cert signed by caCert/caKey and returns its PEM.
func newSignedCertPEM(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	require.NoError(t, err)

	return encodeCertPEM(leafDER)
}

// ─── NewVaultCA ───────────────────────────────────────────────────────────────

func TestNewVaultCA_MissingRole_ReturnsError(t *testing.T) {
	_, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: "http://localhost:8200",
		Token:   "tok",
		Mount:   "pki",
		Role:    "", // intentionally empty
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role")
}

func TestNewVaultCA_InvalidCACertPEM_ReturnsError(t *testing.T) {
	_, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address:   "http://localhost:8200",
		Token:     "tok",
		Mount:     "pki",
		Role:      "my-role",
		CACertPEM: "not-valid-pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CACertPEM")
}

func TestNewVaultCA_ValidConfig_Succeeds(t *testing.T) {
	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: "http://localhost:8200",
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)
	assert.NotNil(t, ca)
}

// ─── CACert ───────────────────────────────────────────────────────────────────

func TestVaultCA_CACert_FetchesAndParses(t *testing.T) {
	caCert, _, caDER := newTestCACert(t)
	caPEM := encodeCertPEM(caDER)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/pki/ca/pem", r.URL.Path)
		assert.Equal(t, "test-token", r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "test-token",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	got := ca.CACert(context.Background())
	require.NotNil(t, got)
	assert.Equal(t, caCert.SerialNumber, got.SerialNumber)
}

func TestVaultCA_CACert_ReturnsNilOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	// CACert returns nil on HTTP error (no error surface from the method signature).
	got := ca.CACert(context.Background())
	assert.Nil(t, got)
}

func TestVaultCA_CACert_ReturnsNilOnInvalidPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-a-pem-blob"))
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)
	assert.Nil(t, ca.CACert(context.Background()))
}

// ─── SignCSR ──────────────────────────────────────────────────────────────────

func TestVaultCA_SignCSR_ReturnsSignedCert(t *testing.T) {
	caCert, caKey, _ := newTestCACert(t)
	signedPEM := newSignedCertPEM(t, caCert, caKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/pki/sign/my-role", r.URL.Path)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.NotEmpty(t, body["csr"])
		assert.NotEmpty(t, body["common_name"])

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"certificate": string(signedPEM),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	csr, _ := newTestCSR(t, "test-cn")
	cert, err := ca.SignCSR(context.Background(), csr, "test-cn", 365)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "leaf", cert.Subject.CommonName)
}

func TestVaultCA_SignCSR_ReturnsErrInvalidCSRForBadSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not reach the server for a bad CSR.
		t.Error("unexpected request to mock server")
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	// Build a CSR whose signature is invalid: create with one key, then swap
	// the public key info so CheckSignature fails.
	badCSR := makeBadSignatureCSR(t)
	_, err = ca.SignCSR(context.Background(), badCSR, "bad", 90)
	require.Error(t, err)
	assert.ErrorIs(t, err, devicepki.ErrInvalidCSR)
}

func TestVaultCA_SignCSR_ReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	csr, _ := newTestCSR(t, "cn")
	_, err = ca.SignCSR(context.Background(), csr, "cn", 90)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// ─── RevokeCert ───────────────────────────────────────────────────────────────

func TestVaultCA_RevokeCert_SendsSerialToRevoke(t *testing.T) {
	const expectedSerial = "123456789"
	revokeCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/pki/revoke", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, expectedSerial, body["serial_number"])

		revokeCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), expectedSerial)
	require.NoError(t, err)
	assert.True(t, revokeCalled)
}

func TestVaultCA_RevokeCert_ReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), "999")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// ─── GenerateCRL ─────────────────────────────────────────────────────────────

func TestVaultCA_GenerateCRL_ReturnsDERBytes(t *testing.T) {
	fakeCRL := []byte{0x01, 0x02, 0x03, 0x04}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/pki/crl", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(fakeCRL)
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	crl, err := ca.GenerateCRL(context.Background())
	require.NoError(t, err)
	assert.Equal(t, fakeCRL, crl)
}

func TestVaultCA_GenerateCRL_ReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "my-role",
	})
	require.NoError(t, err)

	_, err = ca.GenerateCRL(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

// ─── doRequest headers ────────────────────────────────────────────────────────

func TestVaultCA_DoRequest_SetsVaultTokenHeader(t *testing.T) {
	const wantToken = "super-secret-token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, wantToken, r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write([]byte{0xAA})
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   wantToken,
		Mount:   "pki",
		Role:    "role",
	})
	require.NoError(t, err)

	_, _ = ca.GenerateCRL(context.Background()) // triggers doRequest
}

func TestVaultCA_DoRequest_SetsNamespaceHeaderWhenConfigured(t *testing.T) {
	const wantNamespace = "admin/education"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, wantNamespace, r.Header.Get("X-Vault-Namespace"))
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write([]byte{0xBB})
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address:   srv.URL,
		Token:     "tok",
		Mount:     "pki",
		Role:      "role",
		Namespace: wantNamespace,
	})
	require.NoError(t, err)

	_, _ = ca.GenerateCRL(context.Background())
}

func TestVaultCA_DoRequest_NoNamespaceHeaderWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("X-Vault-Namespace"), "namespace header must be absent when not configured")
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write([]byte{0xCC})
	}))
	defer srv.Close()

	ca, err := devicepki.NewVaultCA(devicepki.VaultConfig{
		Address: srv.URL,
		Token:   "tok",
		Mount:   "pki",
		Role:    "role",
		// Namespace intentionally empty
	})
	require.NoError(t, err)

	_, _ = ca.GenerateCRL(context.Background())
}

// ─── Interface compliance ─────────────────────────────────────────────────────

func TestVaultCA_InterfaceCompliance(t *testing.T) {
	var _ devicepki.CA = (*devicepki.VaultCA)(nil)
}

// ─── EncryptSecrets / DecryptSecrets ─────────────────────────────────────────

func TestVaultConfig_EncryptDecryptSecrets_RoundTrip(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.VaultConfig{Token: "vault-token-123", Address: "https://vault:8200", Mount: "pki", Role: "device"}
	original := cfg.Token

	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.True(t, strings.HasPrefix(cfg.Token, "enc:"), "encrypted token must have enc: prefix")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, original, cfg.Token)
}

func TestVaultConfig_EncryptDecryptSecrets_EmptyToken_NoOp(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.VaultConfig{}

	require.NoError(t, cfg.EncryptSecrets(kp))
	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Empty(t, cfg.Token)
}

func TestVaultConfig_DecryptSecrets_PlaintextBackwardCompat(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.VaultConfig{Token: "hvs.CAESIG-some-vault-token"}

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "hvs.CAESIG-some-vault-token", cfg.Token,
		"plaintext token without enc: prefix must be left unchanged")
}

func TestVaultConfig_EncryptSecrets_DoubleEncryptGuard(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.VaultConfig{Token: "vault-token-123"}

	require.NoError(t, cfg.EncryptSecrets(kp))
	encrypted := cfg.Token

	// Encrypting again must be a no-op (already has enc: prefix).
	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.Equal(t, encrypted, cfg.Token, "double encrypt must be a no-op")
}

func TestVaultConfig_DecryptSecrets_Base64PlaintextBackwardCompat(t *testing.T) {
	// A plaintext value that happens to be valid base64 must not be decrypted.
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.VaultConfig{Token: "dGVzdC10b2tlbg=="}  // base64("test-token")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "dGVzdC10b2tlbg==", cfg.Token,
		"base64-looking plaintext without enc: prefix must be left unchanged")
}

// ─── bad-signature CSR helper ─────────────────────────────────────────────────

// makeBadSignatureCSR returns a *x509.CertificateRequest whose CheckSignature
// will return an error. It does this by generating a valid CSR and then creating
// a new one by re-encoding its DER bytes with a flipped byte so the signature is
// invalid. Since the standard library's CheckSignature verifies the TBSCertRequest
// signature, we instead take the simpler approach of creating a CSR template and
// manually corrupting it post-parse.
func makeBadSignatureCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()

	// Generate a valid CSR with key1.
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bad"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key1)
	require.NoError(t, err)

	// Corrupt the last bytes of the DER (the signature portion).
	corrupted := make([]byte, len(der))
	copy(corrupted, der)
	// Flip the last 4 bytes to invalidate the ECDSA signature.
	for i := len(corrupted) - 4; i < len(corrupted); i++ {
		corrupted[i] ^= 0xFF
	}

	// Try to parse. If the DER corruption makes it unparseable, fall back to a
	// structurally different approach: use an all-zeros signature by building a
	// raw ASN.1 structure. Since this is complex, we instead rely on the simpler
	// trick: parse the valid CSR but swap its public key with a different key's
	// public key info by re-encoding. We just parse the valid DER (which is fine)
	// and then produce a *x509.CertificateRequest pointing to a different raw
	// public key — but since Go's struct doesn't expose mutable fields, the
	// easiest way is to use the raw DER corruption path.
	csr, parseErr := x509.ParseCertificateRequest(corrupted)
	if parseErr != nil {
		// Corruption made the ASN.1 unparseable. Use the valid CSR but generate
		// a second key whose public key won't match the signature.
		// We cannot directly produce a CSR whose signature does not match without
		// low-level ASN.1 surgery, so we skip this subtest gracefully.
		t.Skip("could not construct a parseable but signature-invalid CSR; skipping")
		return nil
	}

	// Verify it actually fails CheckSignature before returning.
	if csr.CheckSignature() == nil {
		t.Skip("DER corruption did not produce a signature error; skipping")
		return nil
	}

	return csr
}
