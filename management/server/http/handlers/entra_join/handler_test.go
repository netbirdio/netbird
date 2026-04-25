package entra_join

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
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ed "github.com/netbirdio/netbird/management/server/integrations/entra_device"
	"github.com/netbirdio/netbird/management/server/types"
)

// Local copies of the cert/sig helpers so this package can build independently
// of the cert_validator_test.go helpers (those are in a different package).
func issueCert(t *testing.T, deviceID string) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, base64.StdEncoding.EncodeToString(der)
}

func signNonce(t *testing.T, key *rsa.PrivateKey, nonce []byte) string {
	t.Helper()
	digest := sha256.Sum256(nonce)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

// fakeGraph is a minimal GraphClient for handler tests.
type fakeGraph struct {
	device *ed.GraphDevice
	groups []string
}

func (f *fakeGraph) Device(context.Context, string) (*ed.GraphDevice, error) {
	return f.device, nil
}

func (f *fakeGraph) TransitiveMemberOf(context.Context, string) ([]string, error) {
	return f.groups, nil
}

func (f *fakeGraph) IsCompliant(context.Context, string) (bool, error) {
	return true, nil
}

// fakeEnroller implements ed.PeerEnroller; returns a fixed peer id.
type fakeEnroller struct {
	peerID   string
	lastCall *ed.EnrollPeerInput
}

func (f *fakeEnroller) EnrollEntraDevicePeer(_ context.Context, in ed.EnrollPeerInput) (*ed.EnrollPeerResult, error) {
	c := in
	f.lastCall = &c
	return &ed.EnrollPeerResult{
		PeerID:        f.peerID,
		NetbirdConfig: map[string]any{"dns_domain": "test.local"},
		PeerConfig:    map[string]any{"address": "**********"},
	}, nil
}

func (f *fakeEnroller) DeletePeer(context.Context, string, string) error { return nil }

// -------------------- tests --------------------

func TestHandler_Challenge_ReturnsNonceAndExpiry(t *testing.T) {
	m := ed.NewManager(ed.NewMemoryStore())
	h := NewHandler(m)

	r := mux.NewRouter()
	h.Register(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/join/entra/challenge")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body ed.ChallengeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEmpty(t, body.Nonce)
	assert.True(t, body.ExpiresAt.After(time.Now().UTC()))
}

func TestHandler_Enroll_HappyPath(t *testing.T) {
	store := ed.NewMemoryStore()
	graph := &fakeGraph{
		device: &ed.GraphDevice{ID: "entra-obj-1", DeviceID: "dev-1", AccountEnabled: true},
		groups: []string{"grp-finance"},
	}
	enroller := &fakeEnroller{peerID: "peer-123"}

	m := ed.NewManager(store)
	m.PeerEnroller = enroller
	m.NewGraph = func(_, _, _ string) ed.GraphClient { return graph }

	// Seed integration + mapping.
	ctx := context.Background()
	auth := types.NewEntraDeviceAuth("acct-1")
	auth.TenantID = "tenant-1"
	auth.ClientID = "cid"
	auth.ClientSecret = "cs"
	auth.Enabled = true
	require.NoError(t, store.SaveEntraDeviceAuth(ctx, auth))
	mp := types.NewEntraDeviceAuthMapping("acct-1", auth.ID, "finance", "grp-finance", []string{"nb-vpn"})
	require.NoError(t, store.SaveEntraDeviceMapping(ctx, mp))

	// Stand up the HTTP server.
	router := mux.NewRouter()
	NewHandler(m).Register(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	// 1. GET /challenge
	chResp, err := http.Get(srv.URL + "/join/entra/challenge")
	require.NoError(t, err)
	var challenge ed.ChallengeResponse
	require.NoError(t, json.NewDecoder(chResp.Body).Decode(&challenge))
	_ = chResp.Body.Close()

	// 2. Build enroll request with valid cert + signed nonce.
	key, certB64 := issueCert(t, "dev-1")
	rawNonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	require.NoError(t, err)

	payload, err := json.Marshal(ed.EnrollRequest{
		TenantID:       "tenant-1",
		EntraDeviceID:  "dev-1",
		CertChain:      []string{certB64},
		Nonce:          challenge.Nonce,
		NonceSignature: signNonce(t, key, rawNonce),
		WGPubKey:       "wg-pub-key",
		SSHPubKey:      "ssh-pub-key",
		Hostname:       "laptop-1",
	})
	require.NoError(t, err)

	resp, err := http.Post(srv.URL+"/join/entra/enroll", "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out ed.EnrollResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "peer-123", out.PeerID)
	assert.NotEmpty(t, out.EnrollmentBootstrapToken)
	assert.Equal(t, []string{"nb-vpn"}, out.ResolvedAutoGroups)
	assert.Equal(t, []string{mp.ID}, out.MatchedMappingIDs)

	// The account-manager-side enroller was invoked with the correct input.
	require.NotNil(t, enroller.lastCall, "PeerEnroller was never called")
	assert.Equal(t, "acct-1", enroller.lastCall.AccountID)
	assert.Equal(t, "dev-1", enroller.lastCall.EntraDeviceID)
	assert.Equal(t, []string{"nb-vpn"}, enroller.lastCall.AutoGroups)
	assert.Equal(t, "wg-pub-key", enroller.lastCall.WGPubKey)
}

func TestHandler_Enroll_MapsErrorsToHTTPStatus(t *testing.T) {
	store := ed.NewMemoryStore()
	m := ed.NewManager(store)
	m.PeerEnroller = &fakeEnroller{peerID: "_"}

	router := mux.NewRouter()
	NewHandler(m).Register(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	// Unknown tenant should produce 404 integration_not_found.
	payload := `{"tenant_id":"nope"}`
	resp, err := http.Post(srv.URL+"/join/entra/enroll", "application/json", bytes.NewReader([]byte(payload)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	var body struct{ Code, Message string }
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, string(ed.CodeIntegrationNotFound), body.Code)
}

func TestHandler_Enroll_BadJSON(t *testing.T) {
	m := ed.NewManager(ed.NewMemoryStore())
	m.PeerEnroller = &fakeEnroller{}
	router := mux.NewRouter()
	NewHandler(m).Register(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/join/entra/enroll", "application/json", bytes.NewReader([]byte("{not-json")))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Compile-time assertion that fakes still implement the interfaces.
var _ ed.GraphClient = (*fakeGraph)(nil)
var _ ed.PeerEnroller = (*fakeEnroller)(nil)
