package device_auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// mockCA implements devicepki.CA for testing the CA test endpoint.
type mockCA struct {
	signErr   error
	revokeErr error
	crlErr    error
}

func (m *mockCA) GenerateCA(_ context.Context, _ string) (string, string, error) {
	return "", "", nil
}

func (m *mockCA) SignCSR(_ context.Context, csr *x509.CertificateRequest, cn string, _ int) (*x509.Certificate, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	// Generate a minimal self-signed cert for testing.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func (m *mockCA) RevokeCert(_ context.Context, _ string) error { return m.revokeErr }

func (m *mockCA) GenerateCRL(_ context.Context) ([]byte, error) {
	if m.crlErr != nil {
		return nil, m.crlErr
	}
	return []byte("mock-crl-data"), nil
}

func (m *mockCA) CACert(_ context.Context) *x509.Certificate { return nil }

// mockCAFactory builds a CA factory that returns the given mock.
func mockCAFactory(ca devicepki.CA) func(context.Context, *types.DeviceAuthSettings, string, store.Store, string) (devicepki.CA, error) {
	return func(_ context.Context, _ *types.DeviceAuthSettings, _ string, _ store.Store, _ string) (devicepki.CA, error) {
		return ca, nil
	}
}

// makeRouterWithFactory creates a mux.Router wired to a handler with a custom CA factory.
func makeRouterWithFactory(st store.Store, factory func(context.Context, *types.DeviceAuthSettings, string, store.Store, string) (devicepki.CA, error)) *mux.Router {
	r := mux.NewRouter()
	h := &handler{store: st, caFactory: factory}
	addEndpointsToHandler(h, r)
	return r
}

func TestPostCATest_AllStepsPass(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "builtin"},
	}

	router := makeRouterWithFactory(st, mockCAFactory(&mockCA{}))

	body := `{"ca_type":"builtin"}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp caTestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	require.Len(t, resp.Steps, 5)

	expectedNames := []string{"generate_csr", "sign_certificate", "verify_certificate", "revoke_certificate", "verify_crl"}
	for i, step := range resp.Steps {
		assert.Equal(t, expectedNames[i], step.Name, "step %d name mismatch", i)
		assert.Equal(t, caTestStepOK, step.Status, "step %d status mismatch", i)
	}
}

func TestPostCATest_SignFailure(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "builtin"},
	}

	signErr := errors.New("signing failed")
	router := makeRouterWithFactory(st, mockCAFactory(&mockCA{signErr: signErr}))

	body := `{"ca_type":"builtin"}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp caTestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	require.Len(t, resp.Steps, 5)

	assert.Equal(t, caTestStepOK, resp.Steps[0].Status)      // generate_csr
	assert.Equal(t, caTestStepError, resp.Steps[1].Status)   // sign_certificate
	assert.Equal(t, caTestStepSkipped, resp.Steps[2].Status) // verify_certificate
	assert.Equal(t, caTestStepSkipped, resp.Steps[3].Status) // revoke_certificate
	assert.Equal(t, caTestStepSkipped, resp.Steps[4].Status) // verify_crl
}

func TestPostCATest_RevokeFailure(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "builtin"},
	}

	revokeErr := errors.New("revocation failed")
	router := makeRouterWithFactory(st, mockCAFactory(&mockCA{revokeErr: revokeErr}))

	body := `{"ca_type":"builtin"}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp caTestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	require.Len(t, resp.Steps, 5)

	assert.Equal(t, caTestStepOK, resp.Steps[0].Status)      // generate_csr
	assert.Equal(t, caTestStepOK, resp.Steps[1].Status)      // sign_certificate
	assert.Equal(t, caTestStepOK, resp.Steps[2].Status)      // verify_certificate
	assert.Equal(t, caTestStepError, resp.Steps[3].Status)   // revoke_certificate
	assert.Equal(t, caTestStepSkipped, resp.Steps[4].Status) // verify_crl
}

func TestPostCATest_CRLFailure(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "builtin"},
	}

	crlErr := errors.New("CRL generation failed")
	router := makeRouterWithFactory(st, mockCAFactory(&mockCA{crlErr: crlErr}))

	body := `{"ca_type":"builtin"}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp caTestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	require.Len(t, resp.Steps, 5)

	assert.Equal(t, caTestStepOK, resp.Steps[0].Status)    // generate_csr
	assert.Equal(t, caTestStepOK, resp.Steps[1].Status)    // sign_certificate
	assert.Equal(t, caTestStepOK, resp.Steps[2].Status)    // verify_certificate
	assert.Equal(t, caTestStepOK, resp.Steps[3].Status)    // revoke_certificate
	assert.Equal(t, caTestStepError, resp.Steps[4].Status) // verify_crl
}

func TestPostCATest_RequiresAdmin(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = regularUser("user1")

	router := makeRouterWithFactory(st, mockCAFactory(&mockCA{}))

	body := `{"ca_type":"builtin"}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPostCATest_NoAuth(t *testing.T) {
	st := newMockStore()
	router := makeRouterWithFactory(st, mockCAFactory(&mockCA{}))

	body := `{"ca_type":"builtin"}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// No withAuth call — request has no user auth in context.

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestPostCATest_DoesNotPersistCert verifies that postCATest never calls
// store.SaveDeviceCertificate. The test certificate is issued and revoked entirely
// in-memory (for the builtin CA backend) and must not appear in the store.
func TestPostCATest_DoesNotPersistCert(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "builtin"},
	}

	router := makeRouterWithFactory(st, mockCAFactory(&mockCA{}))

	body := `{"ca_type":"builtin"}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp caTestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)

	// SaveDeviceCertificate must never have been called: no device cert records
	// should exist in the store after running the CA test.
	assert.Empty(t, st.deviceCerts, "postCATest must not persist any device certificates to the store")
}

func TestPostCATest_MergesStoredCredentials(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	// Stored settings have a vault token already set.
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:   "vault",
			CAConfig: `{"address":"https://vault.test","token":"stored-token","mount":"pki","role":"nb","timeout_seconds":5}`,
		},
	}

	var capturedSettings *types.DeviceAuthSettings
	capturingFactory := func(_ context.Context, s *types.DeviceAuthSettings, _ string, _ store.Store, _ string) (devicepki.CA, error) {
		capturedSettings = s
		return &mockCA{}, nil
	}

	router := makeRouterWithFactory(st, capturingFactory)

	// Request sends empty token — stored token should be preserved.
	body := `{"ca_type":"vault","vault":{"address":"https://vault.test","token":"","mount":"pki","role":"nb","timeout_seconds":5}}`
	req := httptest.NewRequest(http.MethodPost, "/device-auth/ca/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedSettings)

	// Verify the merged settings contain the stored token.
	var cfg struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal([]byte(capturedSettings.CAConfig), &cfg))
	assert.Equal(t, "stored-token", cfg.Token)
}
