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
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/devicepki"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ─── mock store ───────────────────────────────────────────────────────────────

// mockStore implements the subset of store.Store used by handler.go.
// Unimplemented methods panic to make missing coverage obvious.
type mockStore struct {
	store.Store // embed to satisfy the full interface; methods below override only what we need

	users              map[string]*types.User
	enrollmentRequests map[string]*types.EnrollmentRequest // key: id
	enrollmentByWGKey  map[string]*types.EnrollmentRequest // key: wgPubKey
	deviceCerts        map[string]*types.DeviceCertificate // key: id
	trustedCAs         map[string]*types.TrustedCA         // key: id
	accountSettings    map[string]*types.Settings          // key: accountID
	accounts           []*types.Account
	peersByWGKey       map[string]*nbpeer.Peer // key: WireGuard public key
}

func newMockStore() *mockStore {
	return &mockStore{
		users:              make(map[string]*types.User),
		enrollmentRequests: make(map[string]*types.EnrollmentRequest),
		enrollmentByWGKey:  make(map[string]*types.EnrollmentRequest),
		deviceCerts:        make(map[string]*types.DeviceCertificate),
		trustedCAs:         make(map[string]*types.TrustedCA),
		accountSettings:    make(map[string]*types.Settings),
		peersByWGKey:       make(map[string]*nbpeer.Peer),
	}
}

func (m *mockStore) GetUserByUserID(_ context.Context, _ store.LockingStrength, userID string) (*types.User, error) {
	u, ok := m.users[userID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "user not found: %s", userID)
	}
	return u, nil
}

func (m *mockStore) ListEnrollmentRequests(_ context.Context, _ store.LockingStrength, accountID string) ([]*types.EnrollmentRequest, error) {
	var out []*types.EnrollmentRequest
	for _, req := range m.enrollmentRequests {
		if req.AccountID == accountID {
			out = append(out, req)
		}
	}
	return out, nil
}

func (m *mockStore) GetEnrollmentRequest(_ context.Context, _ store.LockingStrength, accountID, id string) (*types.EnrollmentRequest, error) {
	req, ok := m.enrollmentRequests[id]
	if !ok || req.AccountID != accountID {
		return nil, status.Errorf(status.NotFound, "enrollment not found: %s", id)
	}
	return req, nil
}

func (m *mockStore) GetEnrollmentRequestByWGKey(_ context.Context, _ store.LockingStrength, accountID, wgPubKey string) (*types.EnrollmentRequest, error) {
	req, ok := m.enrollmentByWGKey[wgPubKey]
	if !ok || req.AccountID != accountID {
		return nil, status.Errorf(status.NotFound, "enrollment not found for key: %s", wgPubKey)
	}
	return req, nil
}

func (m *mockStore) SaveEnrollmentRequest(_ context.Context, _ store.LockingStrength, req *types.EnrollmentRequest) error {
	m.enrollmentRequests[req.ID] = req
	m.enrollmentByWGKey[req.WGPublicKey] = req
	return nil
}

func (m *mockStore) GetAccountSettings(_ context.Context, _ store.LockingStrength, accountID string) (*types.Settings, error) {
	s, ok := m.accountSettings[accountID]
	if !ok {
		return &types.Settings{}, nil
	}
	return s, nil
}

func (m *mockStore) SaveAccountSettings(_ context.Context, accountID string, settings *types.Settings) error {
	m.accountSettings[accountID] = settings
	return nil
}

func (m *mockStore) ListDeviceCertificates(_ context.Context, _ store.LockingStrength, accountID string) ([]*types.DeviceCertificate, error) {
	var out []*types.DeviceCertificate
	for _, cert := range m.deviceCerts {
		if cert.AccountID == accountID {
			out = append(out, cert)
		}
	}
	return out, nil
}

func (m *mockStore) GetDeviceCertificateByID(_ context.Context, _ store.LockingStrength, accountID, id string) (*types.DeviceCertificate, error) {
	cert, ok := m.deviceCerts[id]
	if !ok || cert.AccountID != accountID {
		return nil, status.Errorf(status.NotFound, "device cert not found: %s", id)
	}
	return cert, nil
}

func (m *mockStore) SaveDeviceCertificate(_ context.Context, _ store.LockingStrength, cert *types.DeviceCertificate) error {
	m.deviceCerts[cert.ID] = cert
	return nil
}

func (m *mockStore) ListTrustedCAs(_ context.Context, _ store.LockingStrength, accountID string) ([]*types.TrustedCA, error) {
	var out []*types.TrustedCA
	for _, ca := range m.trustedCAs {
		if ca.AccountID == accountID {
			out = append(out, ca)
		}
	}
	return out, nil
}

func (m *mockStore) SaveTrustedCA(_ context.Context, _ store.LockingStrength, ca *types.TrustedCA) error {
	m.trustedCAs[ca.ID] = ca
	return nil
}

func (m *mockStore) DeleteTrustedCA(_ context.Context, accountID, id string) error {
	ca, ok := m.trustedCAs[id]
	if !ok || ca.AccountID != accountID {
		return status.Errorf(status.NotFound, "trusted CA not found: %s", id)
	}
	delete(m.trustedCAs, id)
	return nil
}

func (m *mockStore) GetPeerByPeerPubKey(_ context.Context, _ store.LockingStrength, wgPubKey string) (*nbpeer.Peer, error) {
	peer, ok := m.peersByWGKey[wgPubKey]
	if !ok {
		return nil, status.Errorf(status.NotFound, "peer not found for key: %s", wgPubKey)
	}
	return peer, nil
}

func (m *mockStore) GetTrustedCAByCRLToken(_ context.Context, token string) (*types.TrustedCA, error) {
	for _, ca := range m.trustedCAs {
		if ca.CRLToken != nil && *ca.CRLToken == token {
			return ca, nil
		}
	}
	return nil, status.Errorf(status.NotFound, "CA not found for CRL token")
}

func (m *mockStore) GetAllAccounts(_ context.Context) []*types.Account {
	return m.accounts
}

// ─── mock pool updater ────────────────────────────────────────────────────────

type mockPoolUpdater struct {
	updatedPool *x509.CertPool
	callCount   int
}

func (m *mockPoolUpdater) UpdateCertPool(pool *x509.CertPool) {
	m.updatedPool = pool
	m.callCount++
}

// ─── mock network map controller ─────────────────────────────────────────────

type mockNetworkMap struct {
	disconnectedAccounts []string
	disconnectedPeers    []string
}

func (m *mockNetworkMap) DisconnectPeers(_ context.Context, accountID string, peerIDs []string) {
	m.disconnectedAccounts = append(m.disconnectedAccounts, accountID)
	m.disconnectedPeers = append(m.disconnectedPeers, peerIDs...)
}

func (m *mockNetworkMap) BufferUpdateAccountPeers(_ context.Context, _ string) error { return nil }
func (m *mockNetworkMap) CountStreams() int                                            { return 0 }

// ─── helpers ──────────────────────────────────────────────────────────────────

// userAuth builds an auth.UserAuth with admin privileges.
func adminAuth(accountID, userID string) auth.UserAuth {
	return auth.UserAuth{
		AccountId: accountID,
		UserId:    userID,
	}
}

// withAuth injects a UserAuth into the request context.
func withAuth(r *http.Request, ua auth.UserAuth) *http.Request {
	return r.WithContext(nbcontext.SetUserAuthInContext(r.Context(), ua))
}

// adminUser returns a User with admin role belonging to the given account.
func adminUser(id, accountID string) *types.User {
	return &types.User{
		Id:        id,
		Role:      types.UserRoleAdmin,
		AccountID: accountID,
	}
}

// regularUser returns a User with regular user role.
func regularUser(id string) *types.User {
	return &types.User{
		Id:   id,
		Role: types.UserRoleUser,
	}
}

// makeRouter sets up a mux.Router with the handler endpoints registered.
func makeRouter(st store.Store, pu certPoolUpdater) *mux.Router {
	r := mux.NewRouter()
	AddEndpoints(st, pu, "", nil, r)
	return r
}

// newTestCSRPEM generates a PEM-encoded PKCS#10 CSR for testing.
func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newTestCSRPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
	return string(pemBytes)
}

// seedBuiltinCA generates a BuiltinCA, persists it in the mock store, and returns the CA
// and the CRL token assigned to the record. Callers that need to request the CRL endpoint
// can use the returned token to construct the path: /device-auth/crl/{token}.
func seedBuiltinCA(t *testing.T, st *mockStore, accountID string) (*devicepki.BuiltinCA, string) {
	t.Helper()
	certPEM, keyPEM, err := devicepki.NewBuiltinCA(accountID)
	require.NoError(t, err)

	ca, err := devicepki.LoadBuiltinCA(certPEM, keyPEM, "")
	require.NoError(t, err)

	// Use a valid 64-char lowercase hex token so the getCRL handler's format check passes.
	crlToken := strings.Repeat("0", 63) + "1"
	caRecord := types.NewBuiltinTrustedCA(accountID, "Test CA", certPEM, keyPEM)
	caRecord.CRLToken = &crlToken
	st.trustedCAs[caRecord.ID] = caRecord

	return ca, crlToken
}

// doRequest performs an HTTP request against the router and returns the recorder.
func doRequest(t *testing.T, router *mux.Router, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	return doRequestWithAuth(t, router, method, path, body, adminAuth("acct1", "user1"))
}

func doRequestWithAuth(t *testing.T, router *mux.Router, method, path string, body interface{}, ua auth.UserAuth) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&reqBody).Encode(body))
	}
	req := httptest.NewRequest(method, path, &reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req = withAuth(req, ua)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// ─── requireAdmin tests ────────────────────────────────────────────────────────

func TestRequireAdmin_NoUserID(t *testing.T) {
	st := newMockStore()
	router := makeRouter(st, nil)

	// Inject UserAuth with empty UserId.
	req := httptest.NewRequest(http.MethodGet, "/device-auth/enrollments", nil)
	req = withAuth(req, auth.UserAuth{AccountId: "acct1", UserId: ""})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireAdmin_NonAdminUser(t *testing.T) {
	st := newMockStore()
	st.users["user-regular"] = regularUser("user-regular")
	router := makeRouter(st, nil)

	rr := doRequestWithAuth(t, router, http.MethodGet, "/device-auth/enrollments", nil,
		adminAuth("acct1", "user-regular"))

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireAdmin_NoContext(t *testing.T) {
	st := newMockStore()
	router := makeRouter(st, nil)

	// No UserAuth injected at all — context will return an error.
	req := httptest.NewRequest(http.MethodGet, "/device-auth/enrollments", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Expect a non-200 response (500 or 401/403).
	assert.NotEqual(t, http.StatusOK, rr.Code)
}

// ─── listEnrollments tests ────────────────────────────────────────────────────

func TestListEnrollments_Empty(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/enrollments", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp []enrollmentResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Empty(t, resp)
}

func TestListEnrollments_ReturnsList(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	req1 := types.NewEnrollmentRequest("acct1", "peer1", "wg-key-1", "csr-pem", "")
	req2 := types.NewEnrollmentRequest("acct1", "peer2", "wg-key-2", "csr-pem", "")
	st.enrollmentRequests[req1.ID] = req1
	st.enrollmentRequests[req2.ID] = req2
	// This one belongs to a different account and must not appear.
	otherReq := types.NewEnrollmentRequest("other-acct", "peer3", "wg-key-3", "csr-pem", "")
	st.enrollmentRequests[otherReq.ID] = otherReq

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodGet, "/device-auth/enrollments", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp []enrollmentResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Len(t, resp, 2)
}

// ─── approveEnrollment tests ──────────────────────────────────────────────────

func TestApproveEnrollment_Success(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	// Seed a real builtin CA so that devicepki.NewCA can load it.
	_, _ = seedBuiltinCA(t, st, "acct1")

	csrPEM := newTestCSRPEM(t, "test-device")
	enrollReq := types.NewEnrollmentRequest("acct1", "peer1", "wg-pub-key", csrPEM, "")
	st.enrollmentRequests[enrollReq.ID] = enrollReq
	st.enrollmentByWGKey[enrollReq.WGPublicKey] = enrollReq

	st.accountSettings["acct1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:           types.DeviceAuthCATypeBuiltin,
			CertValidityDays: 365,
		},
	}

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/enrollments/"+enrollReq.ID+"/approve", nil)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp enrollmentResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, types.EnrollmentStatusApproved, resp.Status)
	assert.Equal(t, enrollReq.ID, resp.ID)

	// Verify the enrollment was updated in the store.
	saved := st.enrollmentRequests[enrollReq.ID]
	assert.Equal(t, types.EnrollmentStatusApproved, saved.Status)

	// Verify a device certificate was saved.
	assert.NotEmpty(t, st.deviceCerts)
}

func TestApproveEnrollment_NotFound(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodPost, "/device-auth/enrollments/nonexistent/approve", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestApproveEnrollment_AlreadyApproved(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	enrollReq := types.NewEnrollmentRequest("acct1", "peer1", "wg-key", "csr", "")
	enrollReq.Status = types.EnrollmentStatusApproved
	st.enrollmentRequests[enrollReq.ID] = enrollReq

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/enrollments/"+enrollReq.ID+"/approve", nil)

	// InvalidArgument maps to 422 Unprocessable Entity.
	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
}

// ─── rejectEnrollment tests ───────────────────────────────────────────────────

func TestRejectEnrollment_Success(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	enrollReq := types.NewEnrollmentRequest("acct1", "peer1", "wg-key", "csr", "")
	st.enrollmentRequests[enrollReq.ID] = enrollReq
	st.enrollmentByWGKey[enrollReq.WGPublicKey] = enrollReq

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/enrollments/"+enrollReq.ID+"/reject",
		map[string]string{"reason": "not authorized"})

	require.Equal(t, http.StatusOK, rr.Code)
	var resp enrollmentResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, types.EnrollmentStatusRejected, resp.Status)
	assert.Equal(t, "not authorized", resp.Reason)

	saved := st.enrollmentRequests[enrollReq.ID]
	assert.Equal(t, types.EnrollmentStatusRejected, saved.Status)
	assert.Equal(t, "not authorized", saved.Reason)
}

func TestRejectEnrollment_NoBody(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	enrollReq := types.NewEnrollmentRequest("acct1", "peer1", "wg-key", "csr", "")
	st.enrollmentRequests[enrollReq.ID] = enrollReq

	router := makeRouter(st, nil)

	// Empty body is allowed — reason defaults to empty string.
	req := httptest.NewRequest(http.MethodPost, "/device-auth/enrollments/"+enrollReq.ID+"/reject", nil)
	req = withAuth(req, adminAuth("acct1", "user1"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp enrollmentResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, types.EnrollmentStatusRejected, resp.Status)
	assert.Empty(t, resp.Reason)
}

func TestRejectEnrollment_MalformedJSON(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	enrollReq := types.NewEnrollmentRequest("acct1", "peer1", "wg-key", "csr", "")
	st.enrollmentRequests[enrollReq.ID] = enrollReq

	router := makeRouter(st, nil)

	req := httptest.NewRequest(http.MethodPost, "/device-auth/enrollments/"+enrollReq.ID+"/reject",
		bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acct1", "user1"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRejectEnrollment_NotFound(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodPost, "/device-auth/enrollments/nonexistent/reject", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestRejectEnrollment_AlreadyRejected(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	enrollReq := types.NewEnrollmentRequest("acct1", "peer1", "wg-key", "csr", "")
	enrollReq.Status = types.EnrollmentStatusRejected
	st.enrollmentRequests[enrollReq.ID] = enrollReq

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/enrollments/"+enrollReq.ID+"/reject",
		map[string]string{"reason": "again"})

	// InvalidArgument maps to 422 Unprocessable Entity.
	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
}

// ─── listDevices tests ────────────────────────────────────────────────────────

func TestListDevices_Empty(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/devices", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp []certResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Empty(t, resp)
}

func TestListDevices_ReturnsList(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert1 := types.NewDeviceCertificate("acct1", "peer1", "wg-key-1", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	cert2 := types.NewDeviceCertificate("acct1", "peer2", "wg-key-2", "serial2", "pem2", now, now.Add(365*24*time.Hour))
	// Different account — should not appear.
	cert3 := types.NewDeviceCertificate("other-acct", "peer3", "wg-key-3", "serial3", "pem3", now, now.Add(365*24*time.Hour))

	st.deviceCerts[cert1.ID] = cert1
	st.deviceCerts[cert2.ID] = cert2
	st.deviceCerts[cert3.ID] = cert3

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodGet, "/device-auth/devices", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp []certResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Len(t, resp, 2)
}

// ─── revokeDevice tests ───────────────────────────────────────────────────────

func TestRevokeDevice_Success(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-1", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	st.deviceCerts[cert.ID] = cert

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/devices/"+cert.ID+"/revoke", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp certResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp.Revoked)
	assert.NotNil(t, resp.RevokedAt)

	// Verify store was updated.
	saved := st.deviceCerts[cert.ID]
	assert.True(t, saved.Revoked)
	assert.NotNil(t, saved.RevokedAt)
}

func TestRevokeDevice_Idempotent(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-1", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	cert.Revoked = true
	cert.RevokedAt = &now
	st.deviceCerts[cert.ID] = cert

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/devices/"+cert.ID+"/revoke", nil)

	// Idempotent: returns 200 without re-saving.
	require.Equal(t, http.StatusOK, rr.Code)
	var resp certResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp.Revoked)
}

func TestRevokeDevice_NotFound(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodPost, "/device-auth/devices/nonexistent/revoke", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// ─── renewDeviceCert tests ────────────────────────────────────────────────────

func TestRenewDeviceCert_RevokesAndResets(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-1", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	st.deviceCerts[cert.ID] = cert

	// Seed an enrollment request so renewDeviceCert can reset it.
	enrollReq := types.NewEnrollmentRequest("acct1", "peer1", "wg-key-1", "csr", "")
	enrollReq.Status = types.EnrollmentStatusApproved
	st.enrollmentRequests[enrollReq.ID] = enrollReq
	st.enrollmentByWGKey["wg-key-1"] = enrollReq

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/devices/"+cert.ID+"/cert/renew", nil)

	require.Equal(t, http.StatusOK, rr.Code)

	// The cert should now be revoked.
	savedCert := st.deviceCerts[cert.ID]
	assert.True(t, savedCert.Revoked)

	// The enrollment request should have been reset to pending.
	savedEnroll := st.enrollmentRequests[enrollReq.ID]
	assert.Equal(t, types.EnrollmentStatusPending, savedEnroll.Status)
	assert.Equal(t, "renewal initiated by admin", savedEnroll.Reason)
}

func TestRenewDeviceCert_AlreadyRevoked(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-1", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	cert.Revoked = true
	cert.RevokedAt = &now
	st.deviceCerts[cert.ID] = cert

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodPost, "/device-auth/devices/"+cert.ID+"/cert/renew", nil)

	// Should still return 200 (cert was already revoked, enrollment reset skipped since no enrollment).
	require.Equal(t, http.StatusOK, rr.Code)
}

// ─── listTrustedCAs tests ─────────────────────────────────────────────────────

func TestListTrustedCAs_Empty(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/trusted-cas", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp []caResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Empty(t, resp)
}

func TestListTrustedCAs_ReturnsList(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	ca1 := types.NewTrustedCA("acct1", "CA One", "pem1")
	ca2 := types.NewTrustedCA("acct1", "CA Two", "pem2")
	// Different account — must not appear.
	ca3 := types.NewTrustedCA("other-acct", "CA Three", "pem3")
	st.trustedCAs[ca1.ID] = ca1
	st.trustedCAs[ca2.ID] = ca2
	st.trustedCAs[ca3.ID] = ca3

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodGet, "/device-auth/trusted-cas", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp []caResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Len(t, resp, 2)
}

// ─── createTrustedCA tests ────────────────────────────────────────────────────

func TestCreateTrustedCA_Success(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accounts = []*types.Account{{Id: "acct1"}}

	poolUpdater := &mockPoolUpdater{}
	router := makeRouter(st, poolUpdater)

	rr := doRequest(t, router, http.MethodPost, "/device-auth/trusted-cas",
		map[string]string{"name": "My CA", "pem": selfSignedCertPEM(t)})

	require.Equal(t, http.StatusOK, rr.Code)
	var resp caResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "My CA", resp.Name)
	assert.NotEmpty(t, resp.ID)

	// Verify pool was rebuilt.
	assert.Equal(t, 1, poolUpdater.callCount)
}

func TestCreateTrustedCA_MissingFields(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	// Missing pem field — returns InvalidArgument which maps to 422.
	rr := doRequest(t, router, http.MethodPost, "/device-auth/trusted-cas",
		map[string]string{"name": "My CA"})

	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
}

func TestCreateTrustedCA_InvalidPEM(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	// PEM block present but contains garbage — parsePEMCert should reject it.
	rr := doRequest(t, router, http.MethodPost, "/device-auth/trusted-cas",
		map[string]string{"name": "My CA", "pem": "-----BEGIN CERTIFICATE-----\nbm90Y2VydA==\n-----END CERTIFICATE-----"})

	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
}

func TestCreateTrustedCA_MalformedJSON(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	req := httptest.NewRequest(http.MethodPost, "/device-auth/trusted-cas",
		bytes.NewBufferString("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acct1", "user1"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// ─── deleteTrustedCA tests ────────────────────────────────────────────────────

func TestDeleteTrustedCA_Success(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accounts = []*types.Account{{Id: "acct1"}}

	ca := types.NewTrustedCA("acct1", "My CA", "pem")
	st.trustedCAs[ca.ID] = ca

	poolUpdater := &mockPoolUpdater{}
	router := makeRouter(st, poolUpdater)

	rr := doRequest(t, router, http.MethodDelete, "/device-auth/trusted-cas/"+ca.ID, nil)

	require.Equal(t, http.StatusOK, rr.Code)

	// CA should be removed from the store.
	assert.Empty(t, st.trustedCAs)

	// Pool should have been rebuilt.
	assert.Equal(t, 1, poolUpdater.callCount)
}

func TestDeleteTrustedCA_NotFound(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodDelete, "/device-auth/trusted-cas/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// ─── getCRL tests ─────────────────────────────────────────────────────────────

func TestGetCRL_Success(t *testing.T) {
	st := newMockStore()
	// CRL endpoint is unauthenticated; no user setup needed.

	// Seed a builtin CA so GetTrustedCAByCRLToken can find it by token.
	_, crlToken := seedBuiltinCA(t, st, "acct1")

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodGet, "/device-auth/crl/"+crlToken, nil)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/pkix-crl", rr.Header().Get("Content-Type"))
	assert.NotEmpty(t, rr.Body.Bytes())
}

func TestGetCRL_NoSettingsStillWorks(t *testing.T) {
	st := newMockStore()

	// Seed a builtin CA — the CRL endpoint only needs to find the CA by token.
	_, crlToken := seedBuiltinCA(t, st, "acct1")

	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodGet, "/device-auth/crl/"+crlToken, nil)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/pkix-crl", rr.Header().Get("Content-Type"))
}

// ─── getSettings tests ────────────────────────────────────────────────────────

func TestGetSettings_NilDeviceAuth(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	// No DeviceAuth set — returns sensible defaults for fresh accounts.
	st.accountSettings["acct1"] = &types.Settings{}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/settings", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp deviceAuthSettingsResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, types.DeviceAuthModeDisabled, resp.Mode)
	assert.Equal(t, types.DeviceAuthEnrollmentManual, resp.EnrollmentMode)
	assert.Equal(t, types.DeviceAuthCATypeBuiltin, resp.CAType)
	assert.Equal(t, 365, resp.CertValidityDays)
}

func TestGetSettings_WithDeviceAuth(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			Mode:             types.DeviceAuthModeCertOnly,
			EnrollmentMode:   types.DeviceAuthEnrollmentManual,
			CAType:           types.DeviceAuthCATypeBuiltin,
			CertValidityDays: 90,
			OCSPEnabled:      true,
		},
	}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/settings", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp deviceAuthSettingsResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, types.DeviceAuthModeCertOnly, resp.Mode)
	assert.Equal(t, types.DeviceAuthEnrollmentManual, resp.EnrollmentMode)
	assert.Equal(t, types.DeviceAuthCATypeBuiltin, resp.CAType)
	assert.Equal(t, 90, resp.CertValidityDays)
	assert.True(t, resp.OCSPEnabled)
}

// ─── updateSettings tests ─────────────────────────────────────────────────────

func TestUpdateSettings_Success(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			Mode: types.DeviceAuthModeDisabled,
		},
	}
	router := makeRouter(st, nil)

	mode := types.DeviceAuthModeCertOnly
	validityDays := 180
	rr := doRequest(t, router, http.MethodPut, "/device-auth/settings", deviceAuthSettingsRequest{
		Mode:             &mode,
		CertValidityDays: &validityDays,
	})

	require.Equal(t, http.StatusOK, rr.Code)
	var resp deviceAuthSettingsResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, types.DeviceAuthModeCertOnly, resp.Mode)
	assert.Equal(t, 180, resp.CertValidityDays)

	// Verify the store was updated.
	saved := st.accountSettings["acct1"]
	require.NotNil(t, saved.DeviceAuth)
	assert.Equal(t, types.DeviceAuthModeCertOnly, saved.DeviceAuth.Mode)
	assert.Equal(t, 180, saved.DeviceAuth.CertValidityDays)
}

func TestUpdateSettings_InitializesNilDeviceAuth(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	// No DeviceAuth set yet.
	st.accountSettings["acct1"] = &types.Settings{}
	router := makeRouter(st, nil)

	mode := types.DeviceAuthModeOptional
	rr := doRequest(t, router, http.MethodPut, "/device-auth/settings", deviceAuthSettingsRequest{
		Mode: &mode,
	})

	require.Equal(t, http.StatusOK, rr.Code)
	saved := st.accountSettings["acct1"]
	require.NotNil(t, saved.DeviceAuth)
	assert.Equal(t, types.DeviceAuthModeOptional, saved.DeviceAuth.Mode)
}

func TestUpdateSettings_MalformedJSON(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	router := makeRouter(st, nil)

	req := httptest.NewRequest(http.MethodPut, "/device-auth/settings",
		bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acct1", "user1"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestUpdateSettings_PartialUpdate_PreservesOtherFields(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			Mode:             types.DeviceAuthModeCertOnly,
			EnrollmentMode:   types.DeviceAuthEnrollmentAttestation,
			CAType:           types.DeviceAuthCATypeBuiltin,
			CertValidityDays: 365,
			OCSPEnabled:      true,
		},
	}
	router := makeRouter(st, nil)

	// Only update OCSPEnabled.
	failOpen := true
	rr := doRequest(t, router, http.MethodPut, "/device-auth/settings", deviceAuthSettingsRequest{
		FailOpenOnOCSPUnavailable: &failOpen,
	})

	require.Equal(t, http.StatusOK, rr.Code)

	saved := st.accountSettings["acct1"]
	require.NotNil(t, saved.DeviceAuth)
	// Other fields should be preserved.
	assert.Equal(t, types.DeviceAuthModeCertOnly, saved.DeviceAuth.Mode)
	assert.Equal(t, types.DeviceAuthEnrollmentAttestation, saved.DeviceAuth.EnrollmentMode)
	assert.Equal(t, 365, saved.DeviceAuth.CertValidityDays)
	assert.True(t, saved.DeviceAuth.OCSPEnabled)
	// Updated field.
	assert.True(t, saved.DeviceAuth.FailOpenOnOCSPUnavailable)
}

// ─── store error propagation tests ───────────────────────────────────────────

// errStore wraps mockStore but overrides specific methods to return errors.
type errStore struct {
	*mockStore
	errOnListEnrollments   bool
	errOnListDevices       bool
	errOnListTrustedCAs    bool
	errOnGetSettings       bool
	errOnSaveSettings      bool
	errOnGetDeviceCert     bool
}

func (e *errStore) ListEnrollmentRequests(ctx context.Context, ls store.LockingStrength, accountID string) ([]*types.EnrollmentRequest, error) {
	if e.errOnListEnrollments {
		return nil, status.Errorf(status.Internal, "list enrollments error")
	}
	return e.mockStore.ListEnrollmentRequests(ctx, ls, accountID)
}

func (e *errStore) ListDeviceCertificates(ctx context.Context, ls store.LockingStrength, accountID string) ([]*types.DeviceCertificate, error) {
	if e.errOnListDevices {
		return nil, status.Errorf(status.Internal, "list devices error")
	}
	return e.mockStore.ListDeviceCertificates(ctx, ls, accountID)
}

func (e *errStore) ListTrustedCAs(ctx context.Context, ls store.LockingStrength, accountID string) ([]*types.TrustedCA, error) {
	if e.errOnListTrustedCAs {
		return nil, status.Errorf(status.Internal, "list trusted CAs error")
	}
	return e.mockStore.ListTrustedCAs(ctx, ls, accountID)
}

func (e *errStore) GetAccountSettings(ctx context.Context, ls store.LockingStrength, accountID string) (*types.Settings, error) {
	if e.errOnGetSettings {
		return nil, status.Errorf(status.Internal, "get settings error")
	}
	return e.mockStore.GetAccountSettings(ctx, ls, accountID)
}

func (e *errStore) SaveAccountSettings(ctx context.Context, accountID string, settings *types.Settings) error {
	if e.errOnSaveSettings {
		return status.Errorf(status.Internal, "save settings error")
	}
	return e.mockStore.SaveAccountSettings(ctx, accountID, settings)
}

func (e *errStore) GetDeviceCertificateByID(ctx context.Context, ls store.LockingStrength, accountID, id string) (*types.DeviceCertificate, error) {
	if e.errOnGetDeviceCert {
		return nil, status.Errorf(status.Internal, "get device cert error")
	}
	return e.mockStore.GetDeviceCertificateByID(ctx, ls, accountID, id)
}

func TestListEnrollments_StoreError(t *testing.T) {
	base := newMockStore()
	base.users["user1"] = adminUser("user1", "acct1")
	st := &errStore{mockStore: base, errOnListEnrollments: true}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/enrollments", nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestListDevices_StoreError(t *testing.T) {
	base := newMockStore()
	base.users["user1"] = adminUser("user1", "acct1")
	st := &errStore{mockStore: base, errOnListDevices: true}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/devices", nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestListTrustedCAs_StoreError(t *testing.T) {
	base := newMockStore()
	base.users["user1"] = adminUser("user1", "acct1")
	st := &errStore{mockStore: base, errOnListTrustedCAs: true}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/trusted-cas", nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestGetSettings_StoreError(t *testing.T) {
	base := newMockStore()
	base.users["user1"] = adminUser("user1", "acct1")
	st := &errStore{mockStore: base, errOnGetSettings: true}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/settings", nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUpdateSettings_StoreGetError(t *testing.T) {
	base := newMockStore()
	base.users["user1"] = adminUser("user1", "acct1")
	st := &errStore{mockStore: base, errOnGetSettings: true}
	router := makeRouter(st, nil)

	mode := types.DeviceAuthModeCertOnly
	rr := doRequest(t, router, http.MethodPut, "/device-auth/settings", deviceAuthSettingsRequest{
		Mode: &mode,
	})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestUpdateSettings_StoreSaveError(t *testing.T) {
	base := newMockStore()
	base.users["user1"] = adminUser("user1", "acct1")
	base.accountSettings["acct1"] = &types.Settings{}
	st := &errStore{mockStore: base, errOnSaveSettings: true}
	router := makeRouter(st, nil)

	mode := types.DeviceAuthModeCertOnly
	rr := doRequest(t, router, http.MethodPut, "/device-auth/settings", deviceAuthSettingsRequest{
		Mode: &mode,
	})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestGetCRL_UnknownToken(t *testing.T) {
	st := newMockStore()
	router := makeRouter(st, nil)

	// Unknown token → 404 (the endpoint must not reveal whether any CA exists).
	rr := doRequest(t, router, http.MethodGet, "/device-auth/crl/deadbeef00000000", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetCRL_MissingToken(t *testing.T) {
	st := newMockStore()
	router := makeRouter(st, nil)

	// No token in path — the route /device-auth/crl/{token} won't match and
	// gorilla/mux returns 405 (method not found) for the root-level path
	// or 404 depending on routing configuration; in either case, not 200.
	rr := doRequest(t, router, http.MethodGet, "/device-auth/crl/", nil)

	assert.NotEqual(t, http.StatusOK, rr.Code)
}

func TestRevokeDevice_SaveError(t *testing.T) {
	base := newMockStore()
	base.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-1", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	base.deviceCerts[cert.ID] = cert

	// Wrap store with one that fails on GetDeviceCertificateByID to test error path.
	st := &errStore{mockStore: base, errOnGetDeviceCert: true}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodPost, "/device-auth/devices/"+cert.ID+"/revoke", nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRevokeDevice_CallsDisconnectPeers(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-1", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	st.deviceCerts[cert.ID] = cert

	// Seed a peer so GetPeerByPeerPubKey can find it.
	st.peersByWGKey["wg-key-1"] = &nbpeer.Peer{ID: "peer-1", AccountID: "acct1", Key: "wg-key-1"}

	nmc := &mockNetworkMap{}
	r := mux.NewRouter()
	AddEndpoints(st, nil, "", nmc, r)

	rr := doRequest(t, r, http.MethodPost, "/device-auth/devices/"+cert.ID+"/revoke", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Len(t, nmc.disconnectedPeers, 1, "DisconnectPeers should be called once")
	assert.Equal(t, "peer-1", nmc.disconnectedPeers[0])
	assert.Equal(t, "acct1", nmc.disconnectedAccounts[0])
}

func TestRevokeDevice_NoPeerFound_DoesNotPanic(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")

	now := time.Now().UTC()
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-missing", "serial1", "pem1", now, now.Add(365*24*time.Hour))
	st.deviceCerts[cert.ID] = cert
	// No peer seeded — GetPeerByPeerPubKey returns NotFound.

	nmc := &mockNetworkMap{}
	r := mux.NewRouter()
	AddEndpoints(st, nil, "", nmc, r)

	rr := doRequest(t, r, http.MethodPost, "/device-auth/devices/"+cert.ID+"/revoke", nil)

	// Should succeed without panicking even when the peer is not found.
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, nmc.disconnectedPeers, "DisconnectPeers should not be called when peer is not found")
}

// ─── rebuildCertPool tests ────────────────────────────────────────────────────

func TestGetSettings_RequireInventoryCheck_Returned(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			Mode:                  types.DeviceAuthModeCertOnly,
			EnrollmentMode:        types.DeviceAuthEnrollmentManual,
			RequireInventoryCheck: true,
		},
	}
	router := makeRouter(st, nil)

	rr := doRequest(t, router, http.MethodGet, "/device-auth/settings", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp deviceAuthSettingsResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp.RequireInventoryCheck)
}

func TestUpdateSettings_RequireInventoryCheck_Saved(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			Mode:           types.DeviceAuthModeDisabled,
			EnrollmentMode: types.DeviceAuthEnrollmentManual,
		},
	}
	router := makeRouter(st, nil)

	requireCheck := true
	rr := doRequest(t, router, http.MethodPut, "/device-auth/settings", deviceAuthSettingsRequest{
		RequireInventoryCheck: &requireCheck,
	})

	require.Equal(t, http.StatusOK, rr.Code)
	var resp deviceAuthSettingsResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp.RequireInventoryCheck)

	saved := st.accountSettings["acct1"]
	require.NotNil(t, saved.DeviceAuth)
	assert.True(t, saved.DeviceAuth.RequireInventoryCheck)
}

func TestRebuildCertPool_NilUpdaterIsNoOp(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accounts = []*types.Account{{Id: "acct1"}}

	ca := types.NewTrustedCA("acct1", "CA One", "pem")
	st.trustedCAs[ca.ID] = ca

	// nil poolUpdater — should not panic.
	router := makeRouter(st, nil)
	rr := doRequest(t, router, http.MethodDelete, "/device-auth/trusted-cas/"+ca.ID, nil)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRebuildCertPool_CallsUpdaterWithAllAccounts(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acct1")
	st.accounts = []*types.Account{
		{Id: "acct1"},
		{Id: "acct2"},
	}

	// acct1 CA.
	ca1 := types.NewTrustedCA("acct1", "CA One", "pem1")
	st.trustedCAs[ca1.ID] = ca1

	// acct2 CA (with a different one to be deleted to trigger the rebuild).
	ca2 := types.NewTrustedCA("acct2", "CA Two", "pem2")
	st.trustedCAs[ca2.ID] = ca2

	// The CA to delete from acct1.
	caToDelete := types.NewTrustedCA("acct1", "CA Delete", "pem3")
	st.trustedCAs[caToDelete.ID] = caToDelete

	poolUpdater := &mockPoolUpdater{}
	router := makeRouter(st, poolUpdater)

	rr := doRequest(t, router, http.MethodDelete, "/device-auth/trusted-cas/"+caToDelete.ID, nil)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 1, poolUpdater.callCount)
}

// ─── cert_approver RBAC tests ─────────────────────────────────────────────────

// certApproverUser returns a User with the cert_approver role.
func certApproverUser(id, accountID string) *types.User {
	return &types.User{
		Id:        id,
		Role:      types.UserRoleCertApprover,
		AccountID: accountID,
	}
}

// certApproverAuth builds an auth.UserAuth for a cert_approver user.
func certApproverAuth(accountID, userID string) auth.UserAuth {
	return auth.UserAuth{
		AccountId: accountID,
		UserId:    userID,
	}
}

// doRequestAs performs an HTTP request with the given UserAuth.
func doRequestAs(t *testing.T, router *mux.Router, method, path string, body interface{}, ua auth.UserAuth) *httptest.ResponseRecorder {
	t.Helper()
	return doRequestWithAuth(t, router, method, path, body, ua)
}

func TestCertApprover_CanListEnrollments(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	st.enrollmentRequests["enroll1"] = &types.EnrollmentRequest{
		ID: "enroll1", AccountID: "acct1", WGPublicKey: "key1",
		Status: types.EnrollmentStatusPending,
	}

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodGet, "/device-auth/enrollments", nil,
		certApproverAuth("acct1", "approver1"))

	require.Equal(t, http.StatusOK, rr.Code)
	var list []map[string]interface{}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&list))
	assert.Len(t, list, 1)
}

func TestCertApprover_CanListDevices(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	st.deviceCerts["cert1"] = &types.DeviceCertificate{
		ID: "cert1", AccountID: "acct1", WGPublicKey: "key1",
	}

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodGet, "/device-auth/devices", nil,
		certApproverAuth("acct1", "approver1"))

	require.Equal(t, http.StatusOK, rr.Code)
}

func TestCertApprover_CanApproveEnrollment(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			Mode:           types.DeviceAuthModeCertOnly,
			EnrollmentMode: types.DeviceAuthEnrollmentManual,
			CAType:         types.DeviceAuthCATypeBuiltin,
		},
	}
	_, _ = seedBuiltinCA(t, st, "acct1")
	csrPEM := newTestCSRPEM(t, "test-device")
	st.enrollmentRequests["enroll1"] = &types.EnrollmentRequest{
		ID: "enroll1", AccountID: "acct1", WGPublicKey: "key1",
		Status: types.EnrollmentStatusPending, CSRPEM: csrPEM,
	}
	st.enrollmentByWGKey["key1"] = st.enrollmentRequests["enroll1"]

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodPost, "/device-auth/enrollments/enroll1/approve", nil,
		certApproverAuth("acct1", "approver1"))

	require.Equal(t, http.StatusOK, rr.Code)
}

func TestCertApprover_CanRejectEnrollment(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	st.enrollmentRequests["enroll1"] = &types.EnrollmentRequest{
		ID: "enroll1", AccountID: "acct1", WGPublicKey: "key1",
		Status: types.EnrollmentStatusPending,
	}
	st.enrollmentByWGKey["key1"] = st.enrollmentRequests["enroll1"]

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodPost, "/device-auth/enrollments/enroll1/reject",
		map[string]string{"reason": "not authorized by IT"},
		certApproverAuth("acct1", "approver1"))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, types.EnrollmentStatusRejected, st.enrollmentRequests["enroll1"].Status)
	assert.Equal(t, "not authorized by IT", st.enrollmentRequests["enroll1"].Reason)
}

func TestCertApprover_CannotUpdateSettings(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{DeviceAuth: &types.DeviceAuthSettings{}}

	router := makeRouter(st, nil)
	mode := types.DeviceAuthModeCertOnly
	rr := doRequestAs(t, router, http.MethodPut, "/device-auth/settings",
		deviceAuthSettingsRequest{Mode: &mode},
		certApproverAuth("acct1", "approver1"))

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestCertApprover_CannotRevokeDevice(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	st.deviceCerts["cert1"] = &types.DeviceCertificate{
		ID: "cert1", AccountID: "acct1", WGPublicKey: "key1",
	}

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodPost, "/device-auth/devices/cert1/revoke", nil,
		certApproverAuth("acct1", "approver1"))

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestCertApprover_CannotDeleteTrustedCA(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	ca := types.NewTrustedCA("acct1", "Test CA", "pem")
	st.trustedCAs[ca.ID] = ca

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodDelete, "/device-auth/trusted-cas/"+ca.ID, nil,
		certApproverAuth("acct1", "approver1"))

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestCertApprover_CannotGetSettings(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")
	st.accountSettings["acct1"] = &types.Settings{DeviceAuth: &types.DeviceAuthSettings{}}

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodGet, "/device-auth/settings", nil,
		certApproverAuth("acct1", "approver1"))

	// GET settings is admin-only.
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestCertApprover_CannotCreateTrustedCA(t *testing.T) {
	st := newMockStore()
	st.users["approver1"] = certApproverUser("approver1", "acct1")

	router := makeRouter(st, nil)
	rr := doRequestAs(t, router, http.MethodPost, "/device-auth/trusted-cas",
		map[string]string{"name": "Test CA", "pem": selfSignedCertPEM(t)},
		certApproverAuth("acct1", "approver1"))

	assert.Equal(t, http.StatusForbidden, rr.Code)
}
