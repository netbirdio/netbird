package rosenpass

import (
	"errors"
	"os"
	"sync"
	"testing"

	rp "cunicu.li/go-rosenpass"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// --- test doubles -----------------------------------------------------------

type addPeerCall struct {
	cfg rp.PeerConfig
}

type removePeerCall struct {
	id rp.PeerID
}

type mockServer struct {
	mu        sync.Mutex
	addCalls  []addPeerCall
	removed   []removePeerCall
	nextID    rp.PeerID
	addErr    error
	removeErr error
	closed    bool
	ran       bool
}

func (m *mockServer) AddPeer(cfg rp.PeerConfig) (rp.PeerID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addCalls = append(m.addCalls, addPeerCall{cfg: cfg})
	if m.addErr != nil {
		return rp.PeerID{}, m.addErr
	}
	// Increment a byte in nextID so distinct peers get distinct IDs.
	m.nextID[0]++
	return m.nextID, nil
}

func (m *mockServer) RemovePeer(id rp.PeerID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed = append(m.removed, removePeerCall{id: id})
	return m.removeErr
}

func (m *mockServer) Run() error   { m.ran = true; return nil }
func (m *mockServer) Close() error { m.closed = true; return nil }

type setPSKCall struct {
	peerKey    string
	psk        wgtypes.Key
	updateOnly bool
}

type mockIface struct {
	mu    sync.Mutex
	calls []setPSKCall
	err   error
}

func (m *mockIface) SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, setPSKCall{peerKey: peerKey, psk: psk, updateOnly: updateOnly})
	return m.err
}

// newTestManager builds a Manager with deterministic spk so tie-break
// against a peer pubkey is controllable from tests. The provided spk byte
// becomes the first byte; remaining bytes are zero.
func newTestManager(spkFirstByte byte, mock *mockServer) *Manager {
	spk := make([]byte, 32)
	spk[0] = spkFirstByte
	return &Manager{
		ifaceName:   "wt0",
		spk:         spk,
		ssk:         make([]byte, 32),
		rpKeyHash:   "test-hash",
		rpPeerIDs:   make(map[string]*rp.PeerID),
		rpWgHandler: NewNetbirdHandler(),
		server:      mock,
	}
}

// validWGKey returns a deterministic 32-byte wireguard public key (base64).
func validWGKey(t *testing.T, lastByte byte) string {
	t.Helper()
	var k wgtypes.Key
	k[31] = lastByte
	return k.String()
}

// --- pure helpers ----------------------------------------------------------

func TestHashRosenpassKey_Deterministic(t *testing.T) {
	key := []byte("hello-rosenpass")
	require.Equal(t, hashRosenpassKey(key), hashRosenpassKey(key))
	require.Len(t, hashRosenpassKey(key), 64) // sha256 hex
}

func TestHashRosenpassKey_DifferentInputsDifferOutputs(t *testing.T) {
	require.NotEqual(t, hashRosenpassKey([]byte("a")), hashRosenpassKey([]byte("b")))
}

func TestGetLogLevel_DefaultWhenUnset(t *testing.T) {
	// Snapshot + unset to exercise the LookupEnv ok=false branch. t.Setenv
	// can only set, not delete, so do it manually with restore via t.Cleanup.
	prev, hadPrev := os.LookupEnv(defaultLogLevelVar)
	require.NoError(t, os.Unsetenv(defaultLogLevelVar))
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(defaultLogLevelVar, prev)
		} else {
			_ = os.Unsetenv(defaultLogLevelVar)
		}
	})
	require.Equal(t, defaultLog.String(), getLogLevel().String())
}

func TestGetLogLevel_Cases(t *testing.T) {
	cases := map[string]string{
		"debug":   "DEBUG",
		"info":    "INFO",
		"warn":    "WARN",
		"error":   "ERROR",
		"unknown": "INFO", // default fallback
	}
	for input, wantStr := range cases {
		input, wantStr := input, wantStr
		t.Run(input, func(t *testing.T) {
			t.Setenv(defaultLogLevelVar, input)
			require.Equal(t, wantStr, getLogLevel().String())
		})
	}
}

func TestFindRandomAvailableUDPPort(t *testing.T) {
	port, err := findRandomAvailableUDPPort()
	require.NoError(t, err)
	require.Greater(t, port, 0)
	require.LessOrEqual(t, port, 65535)
}

// --- addPeer ---------------------------------------------------------------

func TestAddPeer_HigherLocalPubkey_SetsEndpoint(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv) // local spk lexicographically larger

	remotePubKey := make([]byte, 32) // remote spk = all zeros (smaller)
	err := m.addPeer(remotePubKey, "rosenpass-host:7000", "100.1.1.1", validWGKey(t, 1))
	require.NoError(t, err)
	require.Len(t, srv.addCalls, 1)

	ep := srv.addCalls[0].cfg.Endpoint
	require.NotNil(t, ep, "initiator side must set Endpoint")
	require.Equal(t, 7000, ep.Port)
	require.Equal(t, "100.1.1.1", ep.IP.String())
}

func TestAddPeer_HigherLocalPubkey_EndpointIPIsIPv4Mapped(t *testing.T) {
	// Regression guard for the EDESTADDRREQ fix: Endpoint.IP must be 16-byte
	// (IPv4-mapped IPv6) so it matches the AF_INET6 listening socket family.
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	err := m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", validWGKey(t, 1))
	require.NoError(t, err)

	ep := srv.addCalls[0].cfg.Endpoint
	require.NotNil(t, ep)
	require.Len(t, ep.IP, 16, "IPv4 endpoint must be normalized to 16-byte v4-mapped form")
	require.True(t, ep.IP.To4() != nil, "Endpoint must still be detected as IPv4")
}

func TestAddPeer_LowerLocalPubkey_LeavesEndpointNil(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0x00, srv) // local spk smaller

	remotePubKey := make([]byte, 32)
	remotePubKey[0] = 0xFF
	err := m.addPeer(remotePubKey, "rp:5000", "100.1.1.1", validWGKey(t, 2))
	require.NoError(t, err)

	require.Nil(t, srv.addCalls[0].cfg.Endpoint, "responder side must NOT set Endpoint")
}

func TestAddPeer_PresharedKeyPropagated(t *testing.T) {
	srv := &mockServer{}
	psk := &wgtypes.Key{0x42}
	m := newTestManager(0xFF, srv)
	m.preSharedKey = (*[32]byte)(psk)

	err := m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", validWGKey(t, 3))
	require.NoError(t, err)
	require.Equal(t, [32]byte(*psk), [32]byte(srv.addCalls[0].cfg.PresharedKey))
}

func TestAddPeer_InvalidRosenpassAddr_ReturnsError(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv) // initiator path → parses rosenpassAddr

	err := m.addPeer(make([]byte, 32), "not-a-host-port", "100.1.1.1", validWGKey(t, 1))
	require.Error(t, err)
	require.Empty(t, srv.addCalls, "server.AddPeer must not run when address parse fails")
}

func TestAddPeer_InvalidWireGuardPubKey_ReturnsError(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	err := m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", "not-a-valid-key")
	require.Error(t, err)
}

func TestAddPeer_ServerError_Propagates(t *testing.T) {
	srv := &mockServer{addErr: errors.New("boom")}
	m := newTestManager(0xFF, srv)

	err := m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", validWGKey(t, 1))
	require.Error(t, err)
}

// Regression guard for issue #4341 (Android crash). If Run() has not completed
// before OnConnected fires, m.rpWgHandler or m.server may be nil. Without the
// nil guards, m.rpWgHandler.AddPeer panics on nil receiver.
func TestAddPeer_NilHandler_ReturnsErrorNoCrash(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)
	m.rpWgHandler = nil // simulate Run() not yet completed

	err := m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", validWGKey(t, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "wg handler not initialized")
}

func TestAddPeer_NilServer_ReturnsErrorNoCrash(t *testing.T) {
	m := newTestManager(0xFF, nil)
	m.server = nil // simulate Run() not yet completed

	err := m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", validWGKey(t, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "server not initialized")
}

// NewManager must pre-initialize rpWgHandler so the nil-receiver crash from
// issue #4341 cannot occur in the window between NewManager and Run().
func TestNewManager_PreInitializesHandler(t *testing.T) {
	psk := wgtypes.Key{}
	m, err := NewManager(&psk, "wt0")
	require.NoError(t, err)
	require.NotNil(t, m.rpWgHandler, "rpWgHandler must be initialized in NewManager")
}

func TestAddPeer_RecordsPeerID(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	wgKey := validWGKey(t, 5)
	err := m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", wgKey)
	require.NoError(t, err)
	require.Contains(t, m.rpPeerIDs, wgKey)
}

// --- OnConnected / OnDisconnected ------------------------------------------

func TestOnConnected_NilRemotePubKey_NoAddPeer(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	m.OnConnected(validWGKey(t, 1), nil, "100.1.1.1", "rp:5000")
	require.Empty(t, srv.addCalls, "nil remote rosenpass pubkey must skip AddPeer")
	require.Empty(t, m.rpPeerIDs)
}

func TestOnConnected_ValidPubKey_CallsAddPeer(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	wgKey := validWGKey(t, 1)
	m.OnConnected(wgKey, make([]byte, 32), "100.1.1.1", "rp:5000")
	require.Len(t, srv.addCalls, 1)
	require.Contains(t, m.rpPeerIDs, wgKey)
}

func TestOnDisconnected_UnknownPeer_NoOp(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	m.OnDisconnected(validWGKey(t, 99))
	require.Empty(t, srv.removed, "unknown peer key must not call RemovePeer")
}

func TestOnDisconnected_KnownPeer_CallsRemoveAndForgets(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	wgKey := validWGKey(t, 1)
	require.NoError(t, m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", wgKey))
	require.Contains(t, m.rpPeerIDs, wgKey)

	m.OnDisconnected(wgKey)
	require.Len(t, srv.removed, 1)
	require.NotContains(t, m.rpPeerIDs, wgKey, "peer must be forgotten after disconnect")
}

// --- IsPresharedKeyInitialized ---------------------------------------------

func TestIsPresharedKeyInitialized_UnknownPeer_ReturnsFalse(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)
	require.False(t, m.IsPresharedKeyInitialized(validWGKey(t, 1)))
}

func TestIsPresharedKeyInitialized_AddedButNotHandshaken_ReturnsFalse(t *testing.T) {
	srv := &mockServer{}
	m := newTestManager(0xFF, srv)

	wgKey := validWGKey(t, 2)
	require.NoError(t, m.addPeer(make([]byte, 32), "rp:5000", "100.1.1.1", wgKey))
	require.False(t, m.IsPresharedKeyInitialized(wgKey))
}

// --- NetbirdHandler.outputKey ----------------------------------------------

func TestHandler_OutputKey_FirstCallUsesUpdateOnlyFalse(t *testing.T) {
	h := NewNetbirdHandler()
	iface := &mockIface{}
	h.SetInterface(iface)

	pid := rp.PeerID{0x01}
	wgKey := wgtypes.Key{0xAA}
	h.AddPeer(pid, "wt0", rp.Key(wgKey))

	psk := rp.Key{0xBB}
	h.HandshakeCompleted(pid, psk)

	require.Len(t, iface.calls, 1)
	require.False(t, iface.calls[0].updateOnly, "first PSK rotation must use updateOnly=false")
	require.Equal(t, wgKey.String(), iface.calls[0].peerKey)
}

func TestHandler_OutputKey_SubsequentCallsUseUpdateOnlyTrue(t *testing.T) {
	h := NewNetbirdHandler()
	iface := &mockIface{}
	h.SetInterface(iface)

	pid := rp.PeerID{0x02}
	h.AddPeer(pid, "wt0", rp.Key(wgtypes.Key{0xCC}))

	h.HandshakeCompleted(pid, rp.Key{0x01}) // first
	h.HandshakeCompleted(pid, rp.Key{0x02}) // second

	require.Len(t, iface.calls, 2)
	require.False(t, iface.calls[0].updateOnly)
	require.True(t, iface.calls[1].updateOnly, "subsequent rotations must use updateOnly=true")
}

func TestHandler_OutputKey_NilInterface_NoCrashNoCall(t *testing.T) {
	h := NewNetbirdHandler()
	// no SetInterface — iface remains nil
	pid := rp.PeerID{0x03}
	h.AddPeer(pid, "wt0", rp.Key(wgtypes.Key{}))

	// Must not panic.
	h.HandshakeCompleted(pid, rp.Key{})
}

func TestHandler_OutputKey_UnknownPeer_NoCall(t *testing.T) {
	h := NewNetbirdHandler()
	iface := &mockIface{}
	h.SetInterface(iface)

	h.HandshakeCompleted(rp.PeerID{0xFF}, rp.Key{})
	require.Empty(t, iface.calls, "unknown peer id must not trigger SetPresharedKey")
}

func TestHandler_RemovePeer_ClearsInitializedState(t *testing.T) {
	h := NewNetbirdHandler()
	iface := &mockIface{}
	h.SetInterface(iface)

	pid := rp.PeerID{0x04}
	h.AddPeer(pid, "wt0", rp.Key(wgtypes.Key{0xDD}))
	h.HandshakeCompleted(pid, rp.Key{0x01})
	require.True(t, h.IsPeerInitialized(pid))

	h.RemovePeer(pid)
	require.False(t, h.IsPeerInitialized(pid), "RemovePeer must clear initialized flag")
}

func TestHandler_SetInterfaceAfterAddPeer_StillReceivesKey(t *testing.T) {
	h := NewNetbirdHandler()
	pid := rp.PeerID{0x05}
	wgKey := wgtypes.Key{0xEE}
	h.AddPeer(pid, "wt0", rp.Key(wgKey))

	iface := &mockIface{}
	h.SetInterface(iface) // set after AddPeer

	h.HandshakeCompleted(pid, rp.Key{0x42})
	require.Len(t, iface.calls, 1)
	require.Equal(t, wgKey.String(), iface.calls[0].peerKey)
}
