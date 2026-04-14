package devicepki_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/secretenc"
)

// ─── NewSmallstepCA ───────────────────────────────────────────────────────────

func TestNewSmallstepCA_MissingProvisionerToken_ReturnsError(t *testing.T) {
	_, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              "https://ca.example.com:9000",
		ProvisionerToken: "", // intentionally empty
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provisioner_token")
}

func TestNewSmallstepCA_ValidConfig_Succeeds(t *testing.T) {
	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              "https://ca.example.com:9000",
		ProvisionerToken: "my-token",
	})
	require.NoError(t, err)
	assert.NotNil(t, ca)
}

func TestNewSmallstepCA_InvalidRootPEM_ReturnsError(t *testing.T) {
	_, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              "https://ca.example.com:9000",
		ProvisionerToken: "my-token",
		RootPEM:          "not-valid-pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RootPEM")
}

// ─── CACert ───────────────────────────────────────────────────────────────────

func TestSmallstepCA_CACert_FetchesRootCert(t *testing.T) {
	_, _, caDER := newTestCACert(t) // reuse helper from vault_adapter_test.go
	caPEM := string(encodeCertPEM(caDER))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/root", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{"ca": caPEM}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	got := ca.CACert(context.Background())
	require.NotNil(t, got)
	assert.True(t, got.IsCA)
}

func TestSmallstepCA_CACert_ReturnsNilOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	// CACert returns nil on decode failure (non-JSON body from error response).
	got := ca.CACert(context.Background())
	assert.Nil(t, got)
}

func TestSmallstepCA_CACert_ReturnsNilWhenNoPEMInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ca":""}`))
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)
	assert.Nil(t, ca.CACert(context.Background()))
}

// ─── SignCSR ──────────────────────────────────────────────────────────────────

func TestSmallstepCA_SignCSR_SendsCSRAndReturnsCert(t *testing.T) {
	caCert, caKey, _ := newTestCACert(t)
	signedPEM := string(newSignedCertPEM(t, caCert, caKey))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/sign", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.NotEmpty(t, body["csr"])
		assert.Equal(t, "tok", body["ott"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := map[string]interface{}{"crt": signedPEM}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	csr, _ := newTestCSR(t, "peer-key")
	cert, err := ca.SignCSR(context.Background(), csr, "peer-key", 365)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "leaf", cert.Subject.CommonName)
}

func TestSmallstepCA_SignCSR_AcceptsStatusOK(t *testing.T) {
	caCert, caKey, _ := newTestCACert(t)
	signedPEM := string(newSignedCertPEM(t, caCert, caKey))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // some step-ca versions return 200
		resp := map[string]interface{}{"crt": signedPEM}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	csr, _ := newTestCSR(t, "peer-key")
	cert, err := ca.SignCSR(context.Background(), csr, "peer-key", 30)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestSmallstepCA_SignCSR_ReturnsErrInvalidCSRForBadSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected request; bad CSR should be rejected locally")
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	badCSR := makeBadSignatureCSR(t)
	_, err = ca.SignCSR(context.Background(), badCSR, "bad", 90)
	require.Error(t, err)
	assert.ErrorIs(t, err, devicepki.ErrInvalidCSR)
}

func TestSmallstepCA_SignCSR_ReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	csr, _ := newTestCSR(t, "cn")
	_, err = ca.SignCSR(context.Background(), csr, "cn", 90)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

// ─── RevokeCert ───────────────────────────────────────────────────────────────

func TestSmallstepCA_RevokeCert_SendsSerialToRevoke(t *testing.T) {
	const expectedSerial = "9876543210"
	revokeCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/revoke", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, expectedSerial, body["serial"])
		assert.Equal(t, "tok", body["ott"])

		revokeCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), expectedSerial)
	require.NoError(t, err)
	assert.True(t, revokeCalled)
}

func TestSmallstepCA_RevokeCert_ReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "conflict", http.StatusConflict)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	err = ca.RevokeCert(context.Background(), "123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "409")
}

// ─── GenerateCRL ─────────────────────────────────────────────────────────────

func TestSmallstepCA_GenerateCRL_ReturnsDERFromCRLEndpoint(t *testing.T) {
	fakeCRL := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/crl", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(fakeCRL)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	crl, err := ca.GenerateCRL(context.Background())
	require.NoError(t, err)
	assert.Equal(t, fakeCRL, crl)
}

func TestSmallstepCA_GenerateCRL_ReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              srv.URL,
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	_, err = ca.GenerateCRL(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
}

// ─── GenerateCA (not supported) ───────────────────────────────────────────────

func TestSmallstepCA_GenerateCA_ReturnsError(t *testing.T) {
	ca, err := devicepki.NewSmallstepCA(devicepki.SmallstepConfig{
		URL:              "http://localhost:9000",
		ProvisionerToken: "tok",
	})
	require.NoError(t, err)

	_, _, err = ca.GenerateCA(context.Background(), "acct-id")
	require.Error(t, err)
}

// ─── Interface compliance ─────────────────────────────────────────────────────

func TestSmallstepCA_InterfaceCompliance(t *testing.T) {
	var _ devicepki.CA = (*devicepki.SmallstepCA)(nil)
}

// ─── EncryptSecrets / DecryptSecrets ─────────────────────────────────────────

func TestSmallstepConfig_EncryptDecryptSecrets_RoundTrip(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SmallstepConfig{URL: "https://ca.example.com:9000", ProvisionerToken: "provisioner-token-xyz"}
	original := cfg.ProvisionerToken

	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.True(t, strings.HasPrefix(cfg.ProvisionerToken, "enc:"), "encrypted token must have enc: prefix")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, original, cfg.ProvisionerToken)
}

func TestSmallstepConfig_EncryptDecryptSecrets_EmptyToken_NoOp(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SmallstepConfig{}

	require.NoError(t, cfg.EncryptSecrets(kp))
	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Empty(t, cfg.ProvisionerToken)
}

func TestSmallstepConfig_DecryptSecrets_PlaintextBackwardCompat(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SmallstepConfig{ProvisionerToken: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test"}

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test", cfg.ProvisionerToken,
		"plaintext JWT token without enc: prefix must be left unchanged")
}

func TestSmallstepConfig_EncryptSecrets_DoubleEncryptGuard(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SmallstepConfig{ProvisionerToken: "provisioner-token-xyz"}

	require.NoError(t, cfg.EncryptSecrets(kp))
	encrypted := cfg.ProvisionerToken

	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.Equal(t, encrypted, cfg.ProvisionerToken, "double encrypt must be a no-op")
}

func TestSmallstepConfig_DecryptSecrets_Base64PlaintextBackwardCompat(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := devicepki.SmallstepConfig{ProvisionerToken: "cHJvdmlzaW9uZXItdG9rZW4="}  // base64("provisioner-token")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "cHJvdmlzaW9uZXItdG9rZW4=", cfg.ProvisionerToken,
		"base64-looking plaintext without enc: prefix must be left unchanged")
}
