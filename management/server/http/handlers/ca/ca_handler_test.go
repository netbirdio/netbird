package ca

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbca "github.com/netbirdio/netbird/management/server/ca"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	testAccountID = "test-account"
	testUserID    = "test-user"
	testDNSDomain = "netbird.example"
)

// mockCAStore implements nbca.CAStore for testing.
type mockCAStore struct {
	caCerts      []*nbca.CACertificate
	issuedCerts  []*nbca.IssuedCertificate
	issuanceLogs []*nbca.CertIssuanceLog
}

func newMockCAStore() *mockCAStore {
	return &mockCAStore{}
}

func (m *mockCAStore) CreateCACertificate(_ context.Context, ca *nbca.CACertificate) error {
	m.caCerts = append(m.caCerts, ca)
	return nil
}

func (m *mockCAStore) GetCACertificateByID(_ context.Context, accountID, caID string) (*nbca.CACertificate, error) {
	for _, c := range m.caCerts {
		if c.AccountID == accountID && c.ID == caID {
			return c, nil
		}
	}
	return nil, fmt.Errorf("CA not found")
}

func (m *mockCAStore) GetActiveCACertificates(_ context.Context, accountID string) ([]*nbca.CACertificate, error) {
	var active []*nbca.CACertificate
	for _, c := range m.caCerts {
		if c.AccountID == accountID && c.IsActive {
			active = append(active, c)
		}
	}
	return active, nil
}

func (m *mockCAStore) DeactivateCACertificate(_ context.Context, accountID, caID string) error {
	for _, c := range m.caCerts {
		if c.AccountID == accountID && c.ID == caID {
			c.IsActive = false
			return nil
		}
	}
	return fmt.Errorf("CA not found")
}

func (m *mockCAStore) CreateIssuedCertificate(_ context.Context, cert *nbca.IssuedCertificate) error {
	m.issuedCerts = append(m.issuedCerts, cert)
	return nil
}

func (m *mockCAStore) GetIssuedCertificates(_ context.Context, accountID string) ([]*nbca.IssuedCertificate, error) {
	var certs []*nbca.IssuedCertificate
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func (m *mockCAStore) GetIssuedCertificatesByPeer(_ context.Context, accountID, peerID string) ([]*nbca.IssuedCertificate, error) {
	var certs []*nbca.IssuedCertificate
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID && c.PeerID == peerID {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func (m *mockCAStore) GetIssuedCertificateBySerial(_ context.Context, accountID, serialNumber string) (*nbca.IssuedCertificate, error) {
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID && c.SerialNumber == serialNumber {
			return c, nil
		}
	}
	return nil, fmt.Errorf("cert not found")
}

func (m *mockCAStore) RevokeCertificate(_ context.Context, accountID, serialNumber string) error {
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID && c.SerialNumber == serialNumber {
			c.Revoked = true
			return nil
		}
	}
	return fmt.Errorf("cert not found")
}

func (m *mockCAStore) GetExpiringCertificates(_ context.Context, _ string, _ time.Time) ([]*nbca.IssuedCertificate, error) {
	return nil, nil
}

func (m *mockCAStore) CreateCertIssuanceLog(_ context.Context, entry *nbca.CertIssuanceLog) error {
	m.issuanceLogs = append(m.issuanceLogs, entry)
	return nil
}

func (m *mockCAStore) CountCertIssuancesInWindow(_ context.Context, _, _ string, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockCAStore) GetPeersWithActiveWildcardCerts(_ context.Context, _ string) (map[string]struct{}, error) {
	return nil, nil
}

// mockStoreForSettings implements only GetAccountSettings from store.Store.
type mockStoreForSettings struct {
	store.Store
	settings *types.Settings
}

func (m *mockStoreForSettings) GetAccountSettings(_ context.Context, _ store.LockingStrength, _ string) (*types.Settings, error) {
	return m.settings, nil
}

func (m *mockStoreForSettings) SaveAccountSettings(_ context.Context, _ string, settings *types.Settings) error {
	m.settings = settings
	return nil
}

func setupTestHandler(t *testing.T, allowPermission bool) (*handler, *mockCAStore) {
	t.Helper()

	caStore := newMockCAStore()
	caManager := nbca.NewManager(caStore)
	caManager.RegisterSigner(nbca.NewACMEPersistSigner())

	ctrl := gomock.NewController(t)
	permissionsManagerMock := permissions.NewMockManager(ctrl)

	if allowPermission {
		permissionsManagerMock.EXPECT().
			ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.CertificateAuthority, gomock.Any()).
			Return(true, nil).
			AnyTimes()
	} else {
		permissionsManagerMock.EXPECT().
			ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.CertificateAuthority, gomock.Any()).
			Return(false, nil).
			AnyTimes()
	}

	mockStore := &mockStoreForSettings{
		settings: &types.Settings{
			DNSDomain: testDNSDomain,
		},
	}

	accountManager := &mock_server.MockAccountManager{
		GetStoreFunc: func() store.Store {
			return mockStore
		},
	}

	h := newHandler(caManager, accountManager, permissionsManagerMock)
	return h, caStore
}

func newAuthenticatedRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	return nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		UserId:    testUserID,
		AccountId: testAccountID,
	})
}

func TestListCAs(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	// Seed a CA
	caStore.caCerts = append(caStore.caCerts, &nbca.CACertificate{
		ID:             "ca-1",
		AccountID:      testAccountID,
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		Fingerprint:    "abc123",
		NotBefore:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:       time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		IsActive:       true,
		CreatedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/ca")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca", h.listCAs).Methods("GET")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var resp []api.CACertificateResponse
	err := json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	require.Len(t, resp, 1)

	assert.Equal(t, "ca-1", resp[0].Id)
	assert.Equal(t, "abc123", resp[0].Fingerprint)
	assert.True(t, resp[0].IsActive)
	// Should NOT include PEM in list response
	assert.Nil(t, resp[0].CertificatePem)
}

func TestGetCA(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	caStore.caCerts = append(caStore.caCerts, &nbca.CACertificate{
		ID:             "ca-1",
		AccountID:      testAccountID,
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		Fingerprint:    "abc123",
		NotBefore:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:       time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		IsActive:       true,
		CreatedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/ca/ca-1")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca/{caId}", h.getCA).Methods("GET")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var resp api.CACertificateResponse
	err := json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "ca-1", resp.Id)
	// Should include PEM in detail response
	assert.NotNil(t, resp.CertificatePem)
	assert.NotEmpty(t, *resp.CertificatePem)
}

func TestInitCA(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/api/ca")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca", h.initCA).Methods("POST")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var resp api.CACertificateResponse
	err := json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Id)
	assert.NotEmpty(t, resp.Fingerprint)
	assert.True(t, resp.IsActive)
	assert.Len(t, caStore.caCerts, 1)
}

func TestDeactivateCA(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	caStore.caCerts = append(caStore.caCerts, &nbca.CACertificate{
		ID:        "ca-1",
		AccountID: testAccountID,
		IsActive:  true,
	})

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodDelete, "/api/ca/ca-1")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca/{caId}", h.deactivateCA).Methods("DELETE")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.False(t, caStore.caCerts[0].IsActive)
}

func TestRotateCA(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	// Init first CA
	caStore.caCerts = append(caStore.caCerts, &nbca.CACertificate{
		ID:        "ca-1",
		AccountID: testAccountID,
		IsActive:  true,
	})

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/api/ca/rotate")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca/rotate", h.rotateCA).Methods("POST")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var resp api.CACertificateResponse
	err := json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Id)
	// Should have 2 CAs now (original + rotated)
	assert.Len(t, caStore.caCerts, 2)
}

func TestListIssuedCerts(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	caStore.issuedCerts = append(caStore.issuedCerts,
		&nbca.IssuedCertificate{
			ID:           "cert-1",
			AccountID:    testAccountID,
			PeerID:       "peer-1",
			SerialNumber: "1234",
			DNSNames:     []string{"peer1.netbird.example"},
			SigningType:  "internal",
			CreatedAt:    time.Now().UTC(),
		},
		&nbca.IssuedCertificate{
			ID:           "cert-2",
			AccountID:    testAccountID,
			PeerID:       "peer-2",
			SerialNumber: "5678",
			DNSNames:     []string{"peer2.netbird.example"},
			SigningType:  "internal",
			CreatedAt:    time.Now().UTC(),
		},
	)

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/ca/certificates")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca/certificates", h.listIssuedCerts).Methods("GET")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var resp []api.IssuedCertificateResponse
	err := json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Len(t, resp, 2)
}

func TestListIssuedCerts_FilterByPeer(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	caStore.issuedCerts = append(caStore.issuedCerts,
		&nbca.IssuedCertificate{
			ID:           "cert-1",
			AccountID:    testAccountID,
			PeerID:       "peer-1",
			SerialNumber: "1234",
			DNSNames:     []string{"peer1.netbird.example"},
			SigningType:  "internal",
			CreatedAt:    time.Now().UTC(),
		},
		&nbca.IssuedCertificate{
			ID:           "cert-2",
			AccountID:    testAccountID,
			PeerID:       "peer-2",
			SerialNumber: "5678",
			DNSNames:     []string{"peer2.netbird.example"},
			SigningType:  "internal",
			CreatedAt:    time.Now().UTC(),
		},
	)

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/ca/certificates?peer_id=peer-1")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca/certificates", h.listIssuedCerts).Methods("GET")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var resp []api.IssuedCertificateResponse
	err := json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "peer-1", resp[0].PeerId)
}

func TestRevokeCert(t *testing.T) {
	h, caStore := setupTestHandler(t, true)

	caStore.issuedCerts = append(caStore.issuedCerts, &nbca.IssuedCertificate{
		ID:           "cert-1",
		AccountID:    testAccountID,
		PeerID:       "peer-1",
		SerialNumber: "1234",
		CreatedAt:    time.Now().UTC(),
	})

	recorder := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/api/ca/certificates/1234/revoke")

	router := mux.NewRouter()
	router.HandleFunc("/api/ca/certificates/{serialNumber}/revoke", h.revokeCert).Methods("POST")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.True(t, caStore.issuedCerts[0].Revoked)
}

func TestPermissionDenied(t *testing.T) {
	h, _ := setupTestHandler(t, false)

	endpoints := []struct {
		method string
		path   string
		route  string
		handle http.HandlerFunc
	}{
		{"GET", "/api/ca", "/api/ca", h.listCAs},
		{"POST", "/api/ca", "/api/ca", h.initCA},
		{"GET", "/api/ca/ca-1", "/api/ca/{caId}", h.getCA},
		{"DELETE", "/api/ca/ca-1", "/api/ca/{caId}", h.deactivateCA},
		{"POST", "/api/ca/rotate", "/api/ca/rotate", h.rotateCA},
		{"GET", "/api/ca/certificates", "/api/ca/certificates", h.listIssuedCerts},
		{"POST", "/api/ca/certificates/1234/revoke", "/api/ca/certificates/{serialNumber}/revoke", h.revokeCert},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := newAuthenticatedRequest(t, ep.method, ep.path)

			router := mux.NewRouter()
			router.HandleFunc(ep.route, ep.handle).Methods(ep.method)
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)

			assert.Equal(t, http.StatusForbidden, recorder.Code, "expected 403 for %s %s, got %d: %s", ep.method, ep.path, recorder.Code, string(body))
		})
	}
}
