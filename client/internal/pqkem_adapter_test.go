package internal

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/pqkem"
)

// fakePSKSetter records PSK programming and can be made to fail.
type fakePSKSetter struct {
	err   error
	calls int
}

func (f *fakePSKSetter) SetPresharedKey(string, wgtypes.Key, bool) error {
	f.calls++
	return f.err
}

const pqTestPeerKey = "eDQmZp9jhQGX7XdYpHGaFSpAouldr3Sbf7MZRcGTGGQ="

func newPQTestStatus(t *testing.T) *peer.Status {
	t.Helper()
	status := peer.NewRecorder("https://mgm")
	require.NoError(t, status.AddPeer(pqTestPeerKey, "peer.netbird.cloud", "100.64.0.2", ""))
	return status
}

// TestPQCallbackHandler_MarksPeerQuantumResistant reproduces the stale status flag: when
// the KEM answer lands after the connection was set up, the per-peer "Quantum resistance"
// flag was computed without a PSK and never refreshed. Programming the PSK must flag it.
func TestPQCallbackHandler_MarksPeerQuantumResistant(t *testing.T) {
	status := newPQTestStatus(t)
	setter := &fakePSKSetter{}
	h := pqCallbackHandler{wg: setter, applied: newAppliedGenerations(), status: status}

	require.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 1, pqkem.PSK{1}))

	st, err := status.GetPeer(pqTestPeerKey)
	require.NoError(t, err)
	assert.Equal(t, 1, setter.calls, "the PSK must be programmed once")
	assert.True(t, st.RosenpassEnabled, "a programmed PQ PSK must mark the peer quantum resistant")
}

// TestPQCallbackHandler_FailedApplyKeepsFlag verifies the flag only follows a PSK that was
// actually programmed: a failed SetPresharedKey must leave the peer unflagged.
func TestPQCallbackHandler_FailedApplyKeepsFlag(t *testing.T) {
	status := newPQTestStatus(t)
	h := pqCallbackHandler{wg: &fakePSKSetter{err: errors.New("boom")}, applied: newAppliedGenerations(), status: status}

	require.Error(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 1, pqkem.PSK{1}))

	st, err := status.GetPeer(pqTestPeerKey)
	require.NoError(t, err)
	assert.False(t, st.RosenpassEnabled, "a PSK that failed to program must not mark the peer quantum resistant")
}

// TestPQCallbackHandler_UnknownStatusPeerDoesNotFailApply verifies the status update is
// best-effort: a peer missing from the status recorder must not fail the PSK apply.
func TestPQCallbackHandler_UnknownStatusPeerDoesNotFailApply(t *testing.T) {
	setter := &fakePSKSetter{}
	h := pqCallbackHandler{wg: setter, applied: newAppliedGenerations(), status: peer.NewRecorder("https://mgm")}

	assert.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 1, pqkem.PSK{1}))
	assert.Equal(t, 1, setter.calls, "the PSK must still be programmed")
}

// TestAppliedGenerations_DropsStale verifies the out-of-order guard: a generation is
// accepted only when it is strictly newer than the last one applied for that peer, so a
// reordered PSK callback cannot restore an older key over a newer one.
func TestAppliedGenerations_DropsStale(t *testing.T) {
	a := newAppliedGenerations()
	accept := func(peer string, gen uint64) bool {
		ran, err := a.apply(peer, gen, func() error { return nil })
		require.NoError(t, err)
		return ran
	}

	if !accept("peerA", 1) {
		t.Fatal("first generation must be accepted")
	}
	if !accept("peerA", 2) {
		t.Fatal("a newer generation must be accepted")
	}
	if accept("peerA", 2) {
		t.Fatal("re-applying the same generation must be dropped")
	}
	if accept("peerA", 1) {
		t.Fatal("an older generation arriving late must be dropped")
	}
	if !accept("peerA", 3) {
		t.Fatal("a newer generation after a dropped stale one must still be accepted")
	}

	// Generations are tracked independently per peer.
	if !accept("peerB", 1) {
		t.Fatal("a different peer's first generation must be accepted")
	}
}

// blockingPSKSetter holds the first SetPresharedKey call until released, recording the
// key WireGuard ends up with.
type blockingPSKSetter struct {
	mu      sync.Mutex
	calls   int
	last    wgtypes.Key
	entered chan struct{}
	release chan struct{}
}

func (s *blockingPSKSetter) SetPresharedKey(_ string, psk wgtypes.Key, _ bool) error {
	s.mu.Lock()
	s.calls++
	first := s.calls == 1
	s.mu.Unlock()
	if first {
		close(s.entered)
		<-s.release
	}
	s.mu.Lock()
	s.last = psk
	s.mu.Unlock()
	return nil
}

// TestPQCallbackHandler_AppliesGenerationsInOrder covers two PSK callbacks for one peer
// overlapping. The newer generation must be the one WireGuard keeps: with the generation
// checked under a lock but the key set outside it, an older apply that was already
// writing could finish last and restore its stale key.
func TestPQCallbackHandler_AppliesGenerationsInOrder(t *testing.T) {
	setter := &blockingPSKSetter{entered: make(chan struct{}), release: make(chan struct{})}
	h := pqCallbackHandler{wg: setter, applied: newAppliedGenerations()}
	older, newer := pqkem.PSK{3}, pqkem.PSK{4}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		assert.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 3, older))
	}()
	<-setter.entered // the older apply is now inside SetPresharedKey

	go func() {
		defer wg.Done()
		assert.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 4, newer))
	}()
	// Give the newer apply the chance to overtake the blocked older one.
	time.Sleep(50 * time.Millisecond)
	close(setter.release)
	wg.Wait()

	setter.mu.Lock()
	defer setter.mu.Unlock()
	assert.Equal(t, wgtypes.Key(newer), setter.last, "WireGuard must keep the newest generation's PSK")
}

// fakePSKSource returns a fixed PSK for every peer.
type fakePSKSource struct {
	psk pqkem.PSK
	ok  bool
}

func (f fakePSKSource) PSK(pqkem.RemoteID) (pqkem.PSK, bool) { return f.psk, f.ok }

// recordingPSKSetter records the last key programmed.
type recordingPSKSetter struct {
	calls int
	last  wgtypes.Key
}

func (r *recordingPSKSetter) SetPresharedKey(_ string, psk wgtypes.Key, _ bool) error {
	r.calls++
	r.last = psk
	return nil
}

// TestPQPSKReapplier_RestoresRotatedKey reproduces a configure that read the PSK before a
// rotation committed: WireGuard was configured with the old key while the manager already
// holds the new one, and the push of the new key was overwritten. The reapply must
// program the new key again.
func TestPQPSKReapplier_RestoresRotatedKey(t *testing.T) {
	stale, latest := wgtypes.Key{1}, pqkem.PSK{2}
	setter := &recordingPSKSetter{}
	r := &pqPSKReapplier{psks: fakePSKSource{psk: latest, ok: true}, wg: setter, applied: newAppliedGenerations()}

	r.reapply(pqTestPeerKey, &stale)

	assert.Equal(t, 1, setter.calls, "a stale configure must be followed by one reprogram")
	assert.Equal(t, wgtypes.Key(latest), setter.last, "WireGuard must end on the latest PSK")
}

// TestPQPSKReapplier_StrictSentinelReplaced covers strict mode: the configure programmed
// the sentinel because no PSK existed yet, and the first PSK landed right after.
func TestPQPSKReapplier_StrictSentinelReplaced(t *testing.T) {
	sentinel, first := wgtypes.Key{9}, pqkem.PSK{3}
	setter := &recordingPSKSetter{}
	r := &pqPSKReapplier{psks: fakePSKSource{psk: first, ok: true}, wg: setter, applied: newAppliedGenerations()}

	r.reapply(pqTestPeerKey, &sentinel)

	assert.Equal(t, wgtypes.Key(first), setter.last, "the sentinel must be replaced by the first PQ PSK")
}

// TestPQPSKReapplier_NoWriteWhenCurrent: the common case, where the configure already used
// the latest PSK or none exists yet, must not touch WireGuard.
func TestPQPSKReapplier_NoWriteWhenCurrent(t *testing.T) {
	current := pqkem.PSK{4}
	programmed := wgtypes.Key(current)

	setter := &recordingPSKSetter{}
	r := &pqPSKReapplier{psks: fakePSKSource{psk: current, ok: true}, wg: setter, applied: newAppliedGenerations()}
	r.reapply(pqTestPeerKey, &programmed)
	assert.Zero(t, setter.calls, "a configure with the latest PSK needs no reprogram")

	r = &pqPSKReapplier{psks: fakePSKSource{}, wg: setter, applied: newAppliedGenerations()}
	r.reapply(pqTestPeerKey, nil)
	assert.Zero(t, setter.calls, "with no PSK derived yet there is nothing to reprogram")
}

// lockCheckingSource records whether the apply lock was held when the PSK was read.
type lockCheckingSource struct {
	applied    *appliedGenerations
	lockedRead bool
}

func (l *lockCheckingSource) PSK(pqkem.RemoteID) (pqkem.PSK, bool) {
	if l.applied.mu.TryLock() {
		l.applied.mu.Unlock()
	} else {
		l.lockedRead = true
	}
	return pqkem.PSK{5}, true
}

// TestPQPSKReapplier_ReadsUnderApplyLock checks the reapply reads the PSK while holding the
// lock the rotation push takes. Reading it outside would let a push land between the read
// and the write, and the reapply would restore the key it was meant to replace.
func TestPQPSKReapplier_ReadsUnderApplyLock(t *testing.T) {
	applied := newAppliedGenerations()
	src := &lockCheckingSource{applied: applied}
	r := &pqPSKReapplier{psks: src, wg: &recordingPSKSetter{}, applied: applied}

	r.reapply(pqTestPeerKey, &wgtypes.Key{1})

	assert.True(t, src.lockedRead, "the PSK must be read under the apply lock")
}

// pqInitiatorKey sorts above pqTestPeerKey, so its manager is the KEM initiator.
const pqInitiatorKey = "kXQmZp9jhQGX7XdYpHGaFSpAouldr3Sbf7MZRcGTGGQ="

var pqTestOverlay = netip.MustParseAddr("100.64.0.9")

// pqStubTransport is a bound PQ data path that never delivers anything; signalling is all
// these tests exercise.
type pqStubTransport struct{}

func (pqStubTransport) Send(netip.AddrPort, []byte) error { return nil }
func (pqStubTransport) LocalPort() int                    { return DefaultPort }
func (pqStubTransport) Run(func(netip.AddrPort, []byte))  {}
func (pqStubTransport) Close() error                      { return nil }

// newPQHandshakerPair builds the initiator and responder handshakers over real managers.
// The tests play the host, carrying payloads between them as signalling would.
func newPQHandshakerPair(t *testing.T) (initiator, responder pqHandshaker) {
	t.Helper()
	mI := pqkem.NewManager(pqkem.LocalID(pqInitiatorKey), pqCallbackHandler{wg: &fakePSKSetter{}}, nil)
	mR := pqkem.NewManager(pqkem.LocalID(pqTestPeerKey), pqCallbackHandler{wg: &fakePSKSetter{}}, nil)
	mI.Start(pqStubTransport{})
	mR.Start(pqStubTransport{})
	t.Cleanup(mI.Stop)
	t.Cleanup(mR.Stop)
	require.True(t, mI.IsInitiator(pqkem.RemoteID(pqTestPeerKey)), "precondition: roles")
	return pqHandshaker{mgr: mI}, pqHandshaker{mgr: mR}
}

// pqSignalBootstrap runs one signalling offer/answer round that carries the KEM.
func pqSignalBootstrap(t *testing.T, hI, hR pqHandshaker) {
	t.Helper()
	offer, _ := hI.OfferPayload(pqTestPeerKey)
	require.NotEmpty(t, offer, "the initiator must offer the KEM")
	answer, _ := hR.AnswerPayload(pqInitiatorKey, offer)
	require.NotEmpty(t, answer, "the responder must answer the KEM")
	hI.OnAnswer(pqTestPeerKey, answer)
	_, okI := hI.PSK(pqTestPeerKey)
	_, okR := hR.PSK(pqInitiatorKey)
	require.True(t, okI && okR, "precondition: both sides hold a PQ PSK")
}

// TestPQHandshaker_InitiatorDowngrade: the initiator restarts without ML-KEM, so its next
// offer carries no KEM. The responder must drop its PSK, or it keeps programming a key the
// peer no longer has and the WireGuard handshake never completes.
func TestPQHandshaker_InitiatorDowngrade(t *testing.T) {
	hI, hR := newPQHandshakerPair(t)
	pqSignalBootstrap(t, hI, hR)
	status := peer.NewRecorder("https://mgm")
	require.NoError(t, status.AddPeer(pqInitiatorKey, "initiator.netbird.cloud", "100.64.0.3", ""))
	require.NoError(t, status.MarkPeerQuantumResistant(pqInitiatorKey))
	hR.status = status

	hR.AnswerPayload(pqInitiatorKey, nil)

	_, ok := hR.PSK(pqInitiatorKey)
	assert.False(t, ok, "a KEM-less offer from an established initiator must drop the PQ PSK")
	st, err := status.GetPeer(pqInitiatorKey)
	require.NoError(t, err)
	assert.False(t, st.RosenpassEnabled, "a downgraded peer must not be reported quantum resistant")
}

// TestPQHandshaker_ResponderDowngrade: the responder restarts without ML-KEM and answers
// our KEM offer with nothing. The initiator must drop its PSK.
func TestPQHandshaker_ResponderDowngrade(t *testing.T) {
	hI, hR := newPQHandshakerPair(t)
	pqSignalBootstrap(t, hI, hR)
	status := newPQTestStatus(t)
	require.NoError(t, status.MarkPeerQuantumResistant(pqTestPeerKey))
	hI.status = status

	offer, _ := hI.OfferPayload(pqTestPeerKey)
	require.NotEmpty(t, offer, "an established initiator still offers on a new signalling round")
	hI.OnAnswer(pqTestPeerKey, nil)

	_, ok := hI.PSK(pqTestPeerKey)
	assert.False(t, ok, "a KEM-less answer to our KEM offer must drop the PQ PSK")
	st, err := status.GetPeer(pqTestPeerKey)
	require.NoError(t, err)
	assert.False(t, st.RosenpassEnabled, "a downgraded peer must not be reported quantum resistant")
}

// TestPQHandshaker_NonCapablePeerUpgrades: the responder ran without ML-KEM, so the
// initiator marked it non-capable. Once it restarts with ML-KEM it announces its PQ port,
// and the initiator must offer the KEM again instead of staying classical until restart.
func TestPQHandshaker_NonCapablePeerUpgrades(t *testing.T) {
	hI, hR := newPQHandshakerPair(t)

	offer, _ := hI.OfferPayload(pqTestPeerKey)
	require.NotEmpty(t, offer)
	hI.OnAnswer(pqTestPeerKey, nil)
	require.False(t, hI.ShouldSendBootstrapOffer(pqTestPeerKey), "precondition: marked non-capable")

	_, port := hR.AnswerPayload(pqInitiatorKey, nil)
	require.NotZero(t, port, "a peer running ML-KEM must announce its PQ port")
	hI.SetRemoteAddr(pqTestPeerKey, netip.AddrPortFrom(pqTestOverlay, port))

	assert.True(t, hI.ShouldSendBootstrapOffer(pqTestPeerKey), "an announced PQ port must make the peer worth a KEM offer again")
	pqSignalBootstrap(t, hI, hR)
}

// TestPQHandshaker_EmptyAnswerWithoutOfferKeepsHint: an empty answer is only a capability
// signal when it answers our KEM offer. Answering an offer that carried no KEM, it says
// nothing, and must not undo the PQ port the same answer announced.
func TestPQHandshaker_EmptyAnswerWithoutOfferKeepsHint(t *testing.T) {
	hI, _ := newPQHandshakerPair(t)

	offer, _ := hI.OfferPayload(pqTestPeerKey)
	require.NotEmpty(t, offer)
	hI.OnAnswer(pqTestPeerKey, nil)

	hI.SetRemoteAddr(pqTestPeerKey, netip.AddrPortFrom(pqTestOverlay, 1))
	hI.OnAnswer(pqTestPeerKey, nil)

	assert.True(t, hI.ShouldSendBootstrapOffer(pqTestPeerKey), "an empty answer with no KEM offer in flight must not mark the peer non-capable")
}

// TestPQCallbackHandler_RekeyFailedLeavesSeverityToConn: the handler cannot tell an
// offline peer from a real failure, so it must not warn; the connection decides.
func TestPQCallbackHandler_RekeyFailedLeavesSeverityToConn(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()

	var recovered []string
	h := pqCallbackHandler{recoverPQKeyOverSignal: func(k string) { recovered = append(recovered, k) }}
	require.NoError(t, h.OnRekeyFailed(pqkem.RemoteID(pqTestPeerKey)))

	assert.Equal(t, []string{pqTestPeerKey}, recovered, "the failure must still be handed to the connection")
	for _, e := range hook.AllEntries() {
		assert.Greater(t, e.Level, log.WarnLevel, "unexpected %s: %s", e.Level, e.Message)
	}
}
