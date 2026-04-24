package entra_device

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

// -------------------- test doubles --------------------

// fakeGraph implements GraphClient for unit tests. Each call records a counter
// and returns the configured canned response.
type fakeGraph struct {
	mu sync.Mutex

	device        *GraphDevice
	deviceErr     error
	groupIDs      []string
	groupsErr     error
	compliant     bool
	complianceErr error

	deviceCalls     int
	groupCalls      int
	complianceCalls int
	gotDeviceID     string
}

func (f *fakeGraph) Device(_ context.Context, id string) (*GraphDevice, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deviceCalls++
	f.gotDeviceID = id
	return f.device, f.deviceErr
}

func (f *fakeGraph) TransitiveMemberOf(_ context.Context, _ string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groupCalls++
	return append([]string(nil), f.groupIDs...), f.groupsErr
}

func (f *fakeGraph) IsCompliant(_ context.Context, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.complianceCalls++
	return f.compliant, f.complianceErr
}

// recordingEnroller is a PeerEnroller that captures the EnrollPeerInput it
// received so the test can assert the mapping-resolution output was correctly
// forwarded to the peer-registration plumbing.
type recordingEnroller struct {
	mu          sync.Mutex
	calls       []EnrollPeerInput
	err         error
	result      *EnrollPeerResult
	deleteCalls int
	deleteErr   error
}

func (r *recordingEnroller) EnrollEntraDevicePeer(_ context.Context, in EnrollPeerInput) (*EnrollPeerResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, in)
	if r.err != nil {
		return nil, r.err
	}
	if r.result != nil {
		return r.result, nil
	}
	return &EnrollPeerResult{PeerID: "peer-" + fmt.Sprint(len(r.calls))}, nil
}

func (r *recordingEnroller) lastCall(t *testing.T) EnrollPeerInput {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.calls, 1, "expected exactly one EnrollEntraDevicePeer call")
	return r.calls[0]
}

// DeletePeer is the compensation hook; tests record the call count so they can
// assert on orphan-peer cleanup if needed.
func (r *recordingEnroller) DeletePeer(_ context.Context, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteCalls++
	return r.deleteErr
}

// -------------------- helpers --------------------

// seedIntegration installs an EntraDeviceAuth config into m.Store for tenant
// tid and returns the integration object so mappings can be attached.
func seedIntegration(t *testing.T, m *Manager, accountID, tid string, resolution types.MappingResolution) *types.EntraDeviceAuth {
	t.Helper()
	auth := types.NewEntraDeviceAuth(accountID)
	auth.TenantID = tid
	auth.ClientID = "fake-client-id"
	auth.ClientSecret = "fake-client-secret"
	auth.Enabled = true
	auth.MappingResolution = resolution
	require.NoError(t, m.Store.SaveEntraDeviceAuth(context.Background(), auth))
	return auth
}

// seedMapping adds a mapping row to m.Store.
func seedMapping(t *testing.T, m *Manager, auth *types.EntraDeviceAuth, name, groupID string, autoGroups []string, priority int) *types.EntraDeviceAuthMapping {
	t.Helper()
	mp := types.NewEntraDeviceAuthMapping(auth.AccountID, auth.ID, name, groupID, autoGroups)
	mp.Priority = priority
	require.NoError(t, m.Store.SaveEntraDeviceMapping(context.Background(), mp))
	return mp
}

// issueAndSignSelfSigned produces a cert + issued nonce + valid signature so
// the Manager's real cert-validation path exercises end-to-end.
func issueAndSignSelfSigned(t *testing.T, m *Manager, deviceID string) (certB64, nonce, sig string) {
	t.Helper()
	_, key, certB64 := issueSelfSignedRSA(t, deviceID,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	n, _, err := m.NonceStore.Issue()
	require.NoError(t, err)
	rawNonce, err := base64.RawURLEncoding.DecodeString(n)
	require.NoError(t, err)
	sig = signNonceRSA(t, key, rawNonce)
	return certB64, n, sig
}

// -------------------- end-to-end tests --------------------

func TestManager_Enroll_HappyPath_ResolvesMappingAndCallsEnroller(t *testing.T) {
	graph := &fakeGraph{
		device:   &GraphDevice{ID: "entra-obj-id-1", DeviceID: "dev-guid-1", AccountEnabled: true, DisplayName: "laptop-1"},
		groupIDs: []string{"group-finance"},
	}
	enroller := &recordingEnroller{}

	store := NewMemoryStore()
	m := &Manager{
		Store:        store,
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: enroller,
		Clock:        func() time.Time { return time.Now().UTC() },
	}
	auth := seedIntegration(t, m, "acct-1", "tenant-xyz", types.MappingResolutionStrictPriority)
	mapping := seedMapping(t, m, auth, "finance-mapping", "group-finance", []string{"nb-group-vpn", "nb-group-apps"}, 10)
	mapping.Ephemeral = false
	mapping.AllowExtraDNSLabels = true
	require.NoError(t, m.Store.SaveEntraDeviceMapping(context.Background(), mapping))

	// Realistic cert + signed nonce.
	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev-guid-1")

	resp, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID:       "tenant-xyz",
		EntraDeviceID:  "dev-guid-1",
		CertChain:      []string{certB64},
		Nonce:          nonce,
		NonceSignature: sig,
		WGPubKey:       "wg-pubkey-abc",
		SSHPubKey:      "ssh-pubkey-def",
		Hostname:       "laptop-1",
	})
	require.NoError(t, err, "expected enrolment to succeed")

	// Response shape: peer ID + bootstrap token + resolved mapping summary.
	assert.NotEmpty(t, resp.PeerID)
	assert.NotEmpty(t, resp.EnrollmentBootstrapToken)
	assert.Equal(t, string(types.MappingResolutionStrictPriority), resp.ResolutionMode)
	assert.Equal(t, []string{mapping.ID}, resp.MatchedMappingIDs)
	assert.Equal(t, []string{"nb-group-vpn", "nb-group-apps"}, resp.ResolvedAutoGroups)

	// Graph was consulted correctly.
	assert.Equal(t, 1, graph.deviceCalls)
	assert.Equal(t, 1, graph.groupCalls)
	assert.Equal(t, 0, graph.complianceCalls, "compliance must NOT be called when RequireIntuneCompliant is false")
	assert.Equal(t, "dev-guid-1", graph.gotDeviceID)

	// PeerEnroller saw exactly the resolved configuration. This is the
	// verification that the integration with peer registration works:
	// the account-manager side will receive AutoGroups / Ephemeral /
	// AllowExtraDNSLabels / AccountID / EntraDeviceMapping.
	call := enroller.lastCall(t)
	assert.Equal(t, "acct-1", call.AccountID)
	assert.Equal(t, "dev-guid-1", call.EntraDeviceID)
	assert.Equal(t, mapping.ID, call.EntraDeviceMapping)
	assert.Equal(t, []string{"nb-group-vpn", "nb-group-apps"}, call.AutoGroups)
	assert.False(t, call.Ephemeral)
	assert.True(t, call.AllowExtraDNSLabels)
	assert.Equal(t, "wg-pubkey-abc", call.WGPubKey)
	assert.Equal(t, "ssh-pubkey-def", call.SSHPubKey)
	assert.Equal(t, "laptop-1", call.Hostname)

	// Bootstrap token can be consumed exactly once.
	ok, err := m.ValidateBootstrapToken(context.Background(), resp.PeerID, resp.EnrollmentBootstrapToken)
	require.NoError(t, err)
	assert.True(t, ok)
	ok2, err := m.ValidateBootstrapToken(context.Background(), resp.PeerID, resp.EnrollmentBootstrapToken)
	require.NoError(t, err)
	assert.False(t, ok2, "bootstrap tokens are single-use")
}

func TestManager_Enroll_UnionModeMergesAllMappings(t *testing.T) {
	graph := &fakeGraph{
		device:   &GraphDevice{ID: "eobj", DeviceID: "dev", AccountEnabled: true},
		groupIDs: []string{"finance", "dev"},
	}
	enroller := &recordingEnroller{}
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: enroller,
		Clock:        func() time.Time { return time.Now().UTC() },
	}
	auth := seedIntegration(t, m, "acct-2", "tenant-z", types.MappingResolutionUnion)

	f := seedMapping(t, m, auth, "Finance", "finance", []string{"ng-finance"}, 10)
	f.AllowExtraDNSLabels = true
	require.NoError(t, m.Store.SaveEntraDeviceMapping(context.Background(), f))

	d := seedMapping(t, m, auth, "Dev", "dev", []string{"ng-dev"}, 20)
	d.Ephemeral = true
	d.AllowExtraDNSLabels = false
	require.NoError(t, m.Store.SaveEntraDeviceMapping(context.Background(), d))

	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")

	resp, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID:       "tenant-z",
		EntraDeviceID:  "dev",
		CertChain:      []string{certB64},
		Nonce:          nonce,
		NonceSignature: sig,
		WGPubKey:       "wg-k",
	})
	require.NoError(t, err)

	// Both mappings contributed to the EnrollPeerInput.
	call := enroller.lastCall(t)
	assert.ElementsMatch(t, []string{"ng-finance", "ng-dev"}, call.AutoGroups)
	assert.True(t, call.Ephemeral, "union mode: any mapping ephemeral -> peer ephemeral (most restrictive)")
	assert.False(t, call.AllowExtraDNSLabels, "union mode: any mapping denies extra labels -> denied (most restrictive)")
	assert.ElementsMatch(t, []string{f.ID, d.ID}, call.MatchedMappingIDs)
	assert.Equal(t, string(types.MappingResolutionUnion), call.ResolutionMode)
	assert.Equal(t, string(types.MappingResolutionUnion), resp.ResolutionMode)
}

func TestManager_Enroll_RejectsUnknownTenant(t *testing.T) {
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return &fakeGraph{} },
		PeerEnroller: &recordingEnroller{},
		Clock:        func() time.Time { return time.Now().UTC() },
	}
	_, err := m.Enroll(context.Background(), &EnrollRequest{TenantID: "no-such-tenant"})
	require.Error(t, err)
	e, ok := AsError(err)
	require.True(t, ok)
	assert.Equal(t, CodeIntegrationNotFound, e.Code)
}

func TestManager_Enroll_RejectsDisabledIntegration(t *testing.T) {
	graph := &fakeGraph{}
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: &recordingEnroller{},
		Clock:        func() time.Time { return time.Now().UTC() },
	}
	auth := seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)
	auth.Enabled = false
	require.NoError(t, m.Store.SaveEntraDeviceAuth(context.Background(), auth))

	_, err := m.Enroll(context.Background(), &EnrollRequest{TenantID: "t"})
	require.Error(t, err)
	e, _ := AsError(err)
	assert.Equal(t, CodeIntegrationDisabled, e.Code)
}

func TestManager_Enroll_RejectsBadNonce(t *testing.T) {
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return &fakeGraph{} },
		PeerEnroller: &recordingEnroller{},
	}
	seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)

	_, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID: "t",
		Nonce:    "not-an-issued-nonce",
	})
	require.Error(t, err)
	e, _ := AsError(err)
	assert.Equal(t, CodeInvalidNonce, e.Code)
}

func TestManager_Enroll_RejectsDisabledDevice(t *testing.T) {
	graph := &fakeGraph{
		device: &GraphDevice{ID: "eobj", DeviceID: "dev", AccountEnabled: false},
	}
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: &recordingEnroller{},
	}
	seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)
	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")

	_, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID:       "t",
		EntraDeviceID:  "dev",
		CertChain:      []string{certB64},
		Nonce:          nonce,
		NonceSignature: sig,
		WGPubKey:       "wg",
	})
	require.Error(t, err)
	e, _ := AsError(err)
	assert.Equal(t, CodeDeviceDisabled, e.Code)
}

func TestManager_Enroll_RejectsMissingDeviceInGraph(t *testing.T) {
	graph := &fakeGraph{device: nil} // not found in Entra
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: &recordingEnroller{},
	}
	seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)
	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")

	_, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID:       "t",
		EntraDeviceID:  "dev",
		CertChain:      []string{certB64},
		Nonce:          nonce,
		NonceSignature: sig,
		WGPubKey:       "wg",
	})
	require.Error(t, err)
	e, _ := AsError(err)
	assert.Equal(t, CodeDeviceDisabled, e.Code)
}

func TestManager_Enroll_RejectsGraphFailure_FailClosed(t *testing.T) {
	graph := &fakeGraph{
		device:    &GraphDevice{ID: "eobj", DeviceID: "dev", AccountEnabled: true},
		groupsErr: errors.New("simulated 429 rate limit"),
	}
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: &recordingEnroller{},
	}
	seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)
	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")

	_, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID:       "t",
		EntraDeviceID:  "dev",
		CertChain:      []string{certB64},
		Nonce:          nonce,
		NonceSignature: sig,
		WGPubKey:       "wg",
	})
	require.Error(t, err)
	e, _ := AsError(err)
	assert.Equal(t, CodeGroupLookupFailed, e.Code,
		"transient Graph errors must fail CLOSED to avoid over-scoping devices")
}

func TestManager_Enroll_ComplianceRequired_PassesAndFails(t *testing.T) {
	baseGraph := func(compliant bool, complianceErr error) *fakeGraph {
		return &fakeGraph{
			device:        &GraphDevice{ID: "eobj", DeviceID: "dev", AccountEnabled: true},
			groupIDs:      []string{"grp"},
			compliant:     compliant,
			complianceErr: complianceErr,
		}
	}
	build := func(graph *fakeGraph) (*Manager, *recordingEnroller) {
		enroller := &recordingEnroller{}
		m := &Manager{
			Store:        NewMemoryStore(),
			NonceStore:   NewInMemoryNonceStore(time.Minute),
			Cert:         NewCertValidator(nil, nil),
			NewGraph:     func(_, _, _ string) GraphClient { return graph },
			PeerEnroller: enroller,
		}
		auth := seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)
		auth.RequireIntuneCompliant = true
		require.NoError(t, m.Store.SaveEntraDeviceAuth(context.Background(), auth))
		seedMapping(t, m, auth, "mp", "grp", []string{"ng"}, 10)
		return m, enroller
	}
	t.Run("compliant device is enrolled", func(t *testing.T) {
		graph := baseGraph(true, nil)
		m, enroller := build(graph)
		certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")
		_, err := m.Enroll(context.Background(), &EnrollRequest{
			TenantID: "t", EntraDeviceID: "dev",
			CertChain: []string{certB64}, Nonce: nonce, NonceSignature: sig,
			WGPubKey: "wg",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, graph.complianceCalls)
		assert.Len(t, enroller.calls, 1)
	})
	t.Run("non-compliant device is rejected", func(t *testing.T) {
		graph := baseGraph(false, nil)
		m, enroller := build(graph)
		certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")
		_, err := m.Enroll(context.Background(), &EnrollRequest{
			TenantID: "t", EntraDeviceID: "dev",
			CertChain: []string{certB64}, Nonce: nonce, NonceSignature: sig,
			WGPubKey: "wg",
		})
		require.Error(t, err)
		e, _ := AsError(err)
		assert.Equal(t, CodeDeviceNotCompliant, e.Code)
		assert.Empty(t, enroller.calls, "peer must NOT be enrolled when non-compliant")
	})
	t.Run("compliance API failure is treated as fail-closed", func(t *testing.T) {
		graph := baseGraph(true, errors.New("intune api down"))
		m, enroller := build(graph)
		certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")
		_, err := m.Enroll(context.Background(), &EnrollRequest{
			TenantID: "t", EntraDeviceID: "dev",
			CertChain: []string{certB64}, Nonce: nonce, NonceSignature: sig,
			WGPubKey: "wg",
		})
		require.Error(t, err)
		e, _ := AsError(err)
		assert.Equal(t, CodeGroupLookupFailed, e.Code)
		assert.Empty(t, enroller.calls)
	})
}

func TestManager_Enroll_NoMappingMatched(t *testing.T) {
	graph := &fakeGraph{
		device:   &GraphDevice{ID: "eobj", DeviceID: "dev", AccountEnabled: true},
		groupIDs: []string{"random-group-i-have-no-mapping-for"},
	}
	enroller := &recordingEnroller{}
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: enroller,
	}
	auth := seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)
	seedMapping(t, m, auth, "finance-only", "finance", []string{"ng"}, 10)
	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")

	_, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID: "t", EntraDeviceID: "dev",
		CertChain: []string{certB64}, Nonce: nonce, NonceSignature: sig,
		WGPubKey: "wg",
	})
	require.Error(t, err)
	e, _ := AsError(err)
	assert.Equal(t, CodeNoMappingMatched, e.Code)
	assert.Empty(t, enroller.calls, "no peer should be enrolled when no mapping matches")
}

func TestManager_Enroll_DeviceIDMismatchIsRejected(t *testing.T) {
	graph := &fakeGraph{
		device:   &GraphDevice{ID: "eobj", DeviceID: "dev-from-graph", AccountEnabled: true},
		groupIDs: []string{"grp"},
	}
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: &recordingEnroller{},
	}
	seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)

	// Cert's CN will be "dev-in-cert"; client submits a different
	// entra_device_id. The validator should reject this mismatch before
	// calling Graph.
	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev-in-cert")

	_, err := m.Enroll(context.Background(), &EnrollRequest{
		TenantID:       "t",
		EntraDeviceID:  "dev-that-client-claims", // MISMATCH
		CertChain:      []string{certB64},
		Nonce:          nonce,
		NonceSignature: sig,
		WGPubKey:       "wg",
	})
	require.Error(t, err)
	e, _ := AsError(err)
	assert.Equal(t, CodeInvalidCertChain, e.Code)
	assert.Equal(t, 0, graph.deviceCalls, "Graph must not be called on device-id mismatch")
}

func TestManager_Enroll_NonceSingleUse(t *testing.T) {
	// Two enrolment attempts with the same nonce -> first succeeds, second
	// fails with invalid_nonce.
	graph := &fakeGraph{
		device:   &GraphDevice{ID: "eobj", DeviceID: "dev", AccountEnabled: true},
		groupIDs: []string{"grp"},
	}
	enroller := &recordingEnroller{}
	m := &Manager{
		Store:        NewMemoryStore(),
		NonceStore:   NewInMemoryNonceStore(time.Minute),
		Cert:         NewCertValidator(nil, nil),
		NewGraph:     func(_, _, _ string) GraphClient { return graph },
		PeerEnroller: enroller,
	}
	auth := seedIntegration(t, m, "a", "t", types.MappingResolutionStrictPriority)
	seedMapping(t, m, auth, "mp", "grp", []string{"ng"}, 10)
	certB64, nonce, sig := issueAndSignSelfSigned(t, m, "dev")

	req := &EnrollRequest{
		TenantID: "t", EntraDeviceID: "dev",
		CertChain: []string{certB64}, Nonce: nonce, NonceSignature: sig,
		WGPubKey: "wg",
	}
	_, err := m.Enroll(context.Background(), req)
	require.NoError(t, err)

	// Second call: same nonce is now consumed.
	_, err2 := m.Enroll(context.Background(), req)
	require.Error(t, err2)
	e, _ := AsError(err2)
	assert.Equal(t, CodeInvalidNonce, e.Code)
	assert.Len(t, enroller.calls, 1, "second call must not create another peer")
}

// Compile-time guarantee that the fakes satisfy the real interfaces.
var _ GraphClient = (*fakeGraph)(nil)
var _ PeerEnroller = (*recordingEnroller)(nil)
