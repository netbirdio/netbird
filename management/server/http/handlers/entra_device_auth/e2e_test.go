package entra_device_auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	entrajoin "github.com/netbirdio/netbird/management/server/http/handlers/entra_join"
	ed "github.com/netbirdio/netbird/management/server/integrations/entra_device"
)

// e2eFakeGraph satisfies ed.GraphClient; tests configure what the device looks
// like in Microsoft Graph so we can exercise the manager without actually
// hitting graph.microsoft.com.
type e2eFakeGraph struct {
	device *ed.GraphDevice
	groups []string
}

func (f *e2eFakeGraph) Device(context.Context, string) (*ed.GraphDevice, error) {
	return f.device, nil
}
func (f *e2eFakeGraph) TransitiveMemberOf(context.Context, string) ([]string, error) {
	return f.groups, nil
}
func (f *e2eFakeGraph) IsCompliant(context.Context, string) (bool, error) {
	return true, nil
}

// e2eFakeEnroller stands in for the AccountManager.AddPeer path so we can
// observe what the enrollment manager hands off after resolving the mapping.
type e2eFakeEnroller struct {
	calls []ed.EnrollPeerInput
}

func (f *e2eFakeEnroller) EnrollEntraDevicePeer(_ context.Context, in ed.EnrollPeerInput) (*ed.EnrollPeerResult, error) {
	f.calls = append(f.calls, in)
	return &ed.EnrollPeerResult{
		PeerID:        fmt.Sprintf("peer-%d", len(f.calls)),
		NetbirdConfig: map[string]any{"signal_url": "wss://signal.test"},
		PeerConfig:    map[string]any{"address": "100.64.0.5/32"},
	}, nil
}
func (f *e2eFakeEnroller) DeletePeer(context.Context, string, string) error { return nil }

// e2eIssueCert mints a self-signed RSA leaf cert with `deviceID` as Subject
// CN (matching the format the real Windows Entra-joined cert uses: the
// MS-Organization-Access certificate's CN is the device GUID).
func e2eIssueCert(t *testing.T, deviceID string) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, base64.StdEncoding.EncodeToString(der)
}

// e2eSignNonce signs the raw nonce bytes with RSA-PSS / SHA-256, matching the
// signature scheme the production CertValidator accepts for RSA keys.
func e2eSignNonce(t *testing.T, key *rsa.PrivateKey, nonce []byte) string {
	t.Helper()
	digest := sha256.Sum256(nonce)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

// e2eHTTP performs a JSON HTTP request and decodes the response body into
// `out` when non-nil. Returns the status code so callers can assert on it.
func e2eHTTP(t *testing.T, method, url string, body any, out any) int {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		require.NoError(t, err)
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, url, rdr)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.ContentLength != 0 {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
	}
	return resp.StatusCode
}

// TestE2E_AdminAndDeviceFlow exercises the full Entra device authentication
// surface end-to-end against a real httptest server:
//
//  1. Admin configures the integration via PUT /api/integrations/entra-device-auth.
//  2. Admin creates a mapping via POST /api/integrations/entra-device-auth/mappings.
//  3. Device hits GET /join/entra/challenge to obtain a one-shot nonce.
//  4. Device signs the nonce with its (test-only) RSA cert and POSTs to
//     /join/entra/enroll.
//  5. Server resolves the mapping, the fake PeerEnroller records the call,
//     and the device receives a peer config + bootstrap token.
//  6. Admin reads back the integration (secret is masked) and the mappings.
//  7. Admin updates and finally deletes the mapping.
//
// Microsoft Graph and the AccountManager are stubbed (they're external
// dependencies that can't be exercised without a live tenant), but every
// other layer — HTTP routing, JSON serialisation, persistence, cert
// validation, nonce single-use semantics, mapping resolution, bootstrap
// token issuance — is the production code path.
func TestE2E_AdminAndDeviceFlow(t *testing.T) {
	const (
		accountID    = "acct-e2e"
		userID       = "user-e2e"
		tenantID     = "tenant-e2e"
		entraGroup   = "grp-engineering"
		netbirdGroup = "nb-engineering"
		deviceGUID   = "11111111-2222-3333-4444-555555555555"
	)

	// --- arrange ----------------------------------------------------

	store := ed.NewMemoryStore()
	graph := &e2eFakeGraph{
		device: &ed.GraphDevice{
			ID:             "entra-obj-" + deviceGUID,
			DeviceID:       deviceGUID,
			AccountEnabled: true,
			DisplayName:    "test-laptop",
		},
		groups: []string{entraGroup},
	}
	enroller := &e2eFakeEnroller{}

	manager := ed.NewManager(store)
	manager.PeerEnroller = enroller
	manager.NewGraph = func(_, _, _ string) ed.GraphClient { return graph }

	router := mux.NewRouter()

	// Admin CRUD wired without the gorm SQL store: bypass Install() (which
	// requires *gorm.DB) and use the in-memory store directly. The auth
	// resolver returns a fixed (account, user) tuple so we can make
	// authenticated calls without standing up the full middleware stack.
	adminHandler := &Handler{
		Store: store,
		ResolveAuth: func(*http.Request) (string, string, error) {
			return accountID, userID, nil
		},
		// Permit==nil → handler treats it as "allow", same as the
		// InsecureAllowAllForTests path Install() exposes for unit tests.
	}
	adminHandler.Register(router.PathPrefix("/api").Subrouter())

	// Device-facing routes on the root router (no auth middleware — device
	// cert + signed nonce are the credentials).
	entrajoin.NewHandler(manager).Register(router)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// --- 1. admin: configure the integration ------------------------

	configureBody := integrationDTO{
		TenantID:                tenantID,
		ClientID:                "app-client-id",
		ClientSecret:            "super-secret",
		Issuer:                  "https://login.microsoftonline.com/" + tenantID + "/v2.0",
		Audience:                "api://netbird.test",
		Enabled:                 true,
		RequireIntuneCompliant:  false,
		AllowTenantOnlyFallback: false,
		MappingResolution:       "strict_priority",
		RevalidationInterval:    "24h",
	}
	var configured integrationDTO
	status := e2eHTTP(t, http.MethodPut,
		srv.URL+"/api/integrations/entra-device-auth", configureBody, &configured)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, tenantID, configured.TenantID)
	assert.Equal(t, "********", configured.ClientSecret,
		"GET should never echo the plaintext secret back")
	assert.True(t, configured.Enabled)

	// --- 2. admin: create a mapping ---------------------------------

	createBody := mappingDTO{
		Name:                "Engineering",
		EntraGroupID:        entraGroup,
		AutoGroups:          []string{netbirdGroup},
		Ephemeral:           false,
		AllowExtraDNSLabels: false,
		Priority:            10,
		Revoked:             false,
	}
	var created mappingDTO
	status = e2eHTTP(t, http.MethodPost,
		srv.URL+"/api/integrations/entra-device-auth/mappings", createBody, &created)
	require.Equal(t, http.StatusCreated, status)
	require.NotEmpty(t, created.ID, "server should assign an id")
	assert.Equal(t, entraGroup, created.EntraGroupID)
	assert.Equal(t, []string{netbirdGroup}, created.AutoGroups)

	// --- 3. device: GET /challenge ----------------------------------

	chResp, err := http.Get(srv.URL + "/join/entra/challenge")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, chResp.StatusCode)
	var challenge ed.ChallengeResponse
	require.NoError(t, json.NewDecoder(chResp.Body).Decode(&challenge))
	require.NoError(t, chResp.Body.Close())
	require.NotEmpty(t, challenge.Nonce)
	require.True(t, challenge.ExpiresAt.After(time.Now().UTC()))

	// --- 4. device: sign nonce + POST /enroll -----------------------

	key, certB64 := e2eIssueCert(t, deviceGUID)
	rawNonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	require.NoError(t, err)
	signature := e2eSignNonce(t, key, rawNonce)

	enrollReq := ed.EnrollRequest{
		TenantID:       tenantID,
		EntraDeviceID:  deviceGUID,
		CertChain:      []string{certB64},
		Nonce:          challenge.Nonce,
		NonceSignature: signature,
		WGPubKey:       "wg-pubkey-base64",
		SSHPubKey:      "ssh-pubkey-base64",
		Hostname:       "test-laptop",
	}
	var enrollResp ed.EnrollResponse
	status = e2eHTTP(t, http.MethodPost,
		srv.URL+"/join/entra/enroll", enrollReq, &enrollResp)
	require.Equalf(t, http.StatusOK, status, "expected 200, got %d", status)

	// --- 5. assert the device-side response is sane -----------------

	assert.NotEmpty(t, enrollResp.PeerID)
	assert.NotEmpty(t, enrollResp.EnrollmentBootstrapToken,
		"server must hand the device a bootstrap token for the first gRPC Login")
	assert.Equal(t, []string{netbirdGroup}, enrollResp.ResolvedAutoGroups)
	assert.Equal(t, []string{created.ID}, enrollResp.MatchedMappingIDs)
	assert.NotEmpty(t, enrollResp.NetbirdConfig)
	assert.NotEmpty(t, enrollResp.PeerConfig)

	// And the AccountManager-side enroller saw the right input.
	require.Len(t, enroller.calls, 1)
	call := enroller.calls[0]
	assert.Equal(t, accountID, call.AccountID)
	assert.Equal(t, deviceGUID, call.EntraDeviceID)
	assert.Equal(t, []string{netbirdGroup}, call.AutoGroups)
	assert.Equal(t, "wg-pubkey-base64", call.WGPubKey)

	// --- 5b. nonce is single-use ------------------------------------

	// Replaying the same enrollment with the now-burned nonce must fail
	// with 4xx; we don't pin a specific code beyond "client error".
	replayStatus := e2eHTTP(t, http.MethodPost,
		srv.URL+"/join/entra/enroll", enrollReq, nil)
	assert.GreaterOrEqual(t, replayStatus, 400)
	assert.Less(t, replayStatus, 500,
		"replaying a consumed nonce must produce a 4xx, not 5xx")

	// --- 6. admin: read back integration + mappings -----------------

	var fetched integrationDTO
	status = e2eHTTP(t, http.MethodGet,
		srv.URL+"/api/integrations/entra-device-auth", nil, &fetched)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, tenantID, fetched.TenantID)
	assert.Equal(t, "app-client-id", fetched.ClientID)
	assert.Equal(t, "********", fetched.ClientSecret, "secret must stay masked on read")
	// The server stores the parsed duration and re-serialises via
	// time.Duration.String(), which canonicalises "24h" as "24h0m0s". Compare
	// durations rather than strings so the test isn't pinned to that format.
	parsed, err := time.ParseDuration(fetched.RevalidationInterval)
	require.NoError(t, err, "revalidation_interval must be a valid Go duration")
	assert.Equal(t, 24*time.Hour, parsed)

	var listed []mappingDTO
	status = e2eHTTP(t, http.MethodGet,
		srv.URL+"/api/integrations/entra-device-auth/mappings", nil, &listed)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, listed, 1)
	assert.Equal(t, created.ID, listed[0].ID)
	assert.Equal(t, "Engineering", listed[0].Name)

	// --- 7. admin: update + delete the mapping ----------------------

	updateBody := mappingDTO{
		Name:                "Engineering (renamed)",
		EntraGroupID:        entraGroup,
		AutoGroups:          []string{netbirdGroup, "nb-extra"},
		Ephemeral:           true,
		AllowExtraDNSLabels: true,
		Priority:            20,
	}
	var updated mappingDTO
	status = e2eHTTP(t, http.MethodPut,
		srv.URL+"/api/integrations/entra-device-auth/mappings/"+created.ID,
		updateBody, &updated)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "Engineering (renamed)", updated.Name)
	assert.True(t, updated.Ephemeral)
	assert.Equal(t, 20, updated.Priority)
	assert.Equal(t, []string{netbirdGroup, "nb-extra"}, updated.AutoGroups)

	status = e2eHTTP(t, http.MethodDelete,
		srv.URL+"/api/integrations/entra-device-auth/mappings/"+created.ID,
		nil, nil)
	require.Equal(t, http.StatusNoContent, status)

	status = e2eHTTP(t, http.MethodGet,
		srv.URL+"/api/integrations/entra-device-auth/mappings/"+created.ID,
		nil, nil)
	assert.Equal(t, http.StatusNotFound, status,
		"after delete, GET on the mapping must return 404")
}

// TestE2E_DisabledIntegration_RejectsEnrolment makes sure that an admin who
// disables the integration (Enabled=false) breaks the device-facing flow as
// expected, even though the integration row still exists.
func TestE2E_DisabledIntegration_RejectsEnrolment(t *testing.T) {
	const tenantID = "tenant-disabled"

	store := ed.NewMemoryStore()
	manager := ed.NewManager(store)
	manager.PeerEnroller = &e2eFakeEnroller{}
	manager.NewGraph = func(_, _, _ string) ed.GraphClient {
		return &e2eFakeGraph{
			device: &ed.GraphDevice{ID: "x", DeviceID: "x", AccountEnabled: true},
			groups: []string{"x"},
		}
	}

	router := mux.NewRouter()
	(&Handler{
		Store: store,
		ResolveAuth: func(*http.Request) (string, string, error) {
			return "acct", "user", nil
		},
	}).Register(router.PathPrefix("/api").Subrouter())
	entrajoin.NewHandler(manager).Register(router)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Configure the integration with Enabled=false.
	require.Equal(t, http.StatusOK, e2eHTTP(t, http.MethodPut,
		srv.URL+"/api/integrations/entra-device-auth", integrationDTO{
			TenantID:     tenantID,
			ClientID:     "cid",
			ClientSecret: "cs",
			Enabled:      false,
		}, nil))

	// Hitting /enroll for that tenant must be rejected. We only assert
	// 4xx + the `integration_disabled` code so the test stays resilient
	// to future status-code tuning.
	body, _ := json.Marshal(ed.EnrollRequest{TenantID: tenantID})
	resp, err := http.Post(srv.URL+"/join/entra/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.GreaterOrEqual(t, resp.StatusCode, 400)
	assert.Less(t, resp.StatusCode, 500)
	raw, _ := io.ReadAll(resp.Body)
	assert.True(t, strings.Contains(string(raw), string(ed.CodeIntegrationDisabled)),
		"expected error body to surface CodeIntegrationDisabled, got: %s", string(raw))
}
