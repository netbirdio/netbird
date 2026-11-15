package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	testWaitTimeout = 2 * time.Second

	// authTokenLenOffset is where the envelope's token length starts: header(2) + magic(4) + peer ID(36).
	authTokenLenOffset = 2 + 4 + 36
)

// scriptedConn is a listener.Conn whose inbound frames are queued by the test and whose
// outbound frames are recorded.
type scriptedConn struct {
	reads     chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	onWrite   func([]byte)

	mu     sync.Mutex
	writes [][]byte
}

type recordingValidator struct {
	err error

	mu       sync.Mutex
	payloads [][]byte
}

func newScriptedConn() *scriptedConn {
	return &scriptedConn{
		reads:  make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (c *scriptedConn) Read(ctx context.Context, b []byte) (int, error) {
	select {
	case msg := <-c.reads:
		return copy(b, msg), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (c *scriptedConn) Write(_ context.Context, b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	frame := append([]byte(nil), b...)
	c.mu.Lock()
	c.writes = append(c.writes, frame)
	c.mu.Unlock()

	if c.onWrite != nil {
		c.onWrite(frame)
	}
	return len(b), nil
}

func (c *scriptedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func (c *scriptedConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *scriptedConn) Protocol() string {
	return "test"
}

func (c *scriptedConn) MaxMessageSize() int {
	return messages.MaxMessageSize
}

func (c *scriptedConn) deliver(t *testing.T, frame []byte) {
	t.Helper()
	select {
	case c.reads <- frame:
	case <-time.After(testWaitTimeout):
		t.Fatal("scripted connection read queue is full")
	}
}

func (c *scriptedConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *scriptedConn) frames() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.writes...)
}

func (c *scriptedConn) waitFrames(t *testing.T, n int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(testWaitTimeout)
	for {
		frames := c.frames()
		if len(frames) >= n {
			return frames
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d written frames, got %d", n, len(frames))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *scriptedConn) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(testWaitTimeout):
		t.Fatal("connection was not closed")
	}
}

func (v *recordingValidator) Validate(credentials any) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	payload, _ := credentials.([]byte)
	v.payloads = append(v.payloads, append([]byte(nil), payload...))
	return v.err
}

func (v *recordingValidator) calls() [][]byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([][]byte(nil), v.payloads...)
}

func TestRelay_AuthV1ResponseIsUnchanged(t *testing.T) {
	validator := &recordingValidator{}
	relay := newTestRelay(t, validator)
	peerID := messages.HashID("v1-client")
	token := []byte("v1-token")
	auth, err := messages.MarshalAuthMsg(peerID, token)
	require.NoError(t, err)

	conn := newScriptedConn()
	conn.deliver(t, auth)
	relay.Accept(conn)

	frames := conn.waitFrames(t, 1)
	want, err := messages.MarshalAuthResponse(relay.instanceURL.String())
	require.NoError(t, err)
	assert.Equal(t, want, frames[0], "a v1 client must receive the same response bytes as today")
	assert.Equal(t, [][]byte{token}, validator.calls(), "the validator must receive the v1 token bytes")
	assert.False(t, conn.isClosed(), "an authenticated v1 connection must stay open")

	item, ok := relay.store.Peer(peerID)
	require.True(t, ok, "the peer must be stored after the response")
	assert.Equal(t, messages.ProtocolV1, item.(*Peer).Version(), "a v1 client selects v1")
}

const testPhaseSecret = "relay-auth-secret"

// signedExtension returns the auth extension of a client that holds the phase
// Management signed with secret for peerID.
func signedExtension(t *testing.T, secret string, peerID messages.PeerID, period time.Duration) ([]byte, alignedhb.SignedPhase) {
	t.Helper()
	signer, err := phasesig.NewSigner(secret)
	require.NoError(t, err)
	sp, err := signer.SignedPhase(peerID, period, time.Now())
	require.NoError(t, err)
	ext, err := messages.MarshalAuthExtension(messages.AuthExtension{
		PeriodSeconds: uint16(period / time.Second),
		SignedPhase: &messages.AuthSignedPhase{
			PhaseMs:   uint32(sp.Phase.Milliseconds()),
			Day:       sp.Day,
			Signature: sp.Signature,
		},
	})
	require.NoError(t, err)
	return ext, sp
}

// newAlignedTestRelay returns a relay whose connections tick every second
// instead of every 30. The floor is lowered on the unexported field, past the
// config check that keeps production limits inside the default range.
func newAlignedTestRelay(t *testing.T, validator Validator) *Relay {
	t.Helper()
	relay := newAlignedTestRelayLimits(t, validator, alignedhb.PeriodLimits{})
	relay.periodLimits = alignedhb.PeriodLimits{Min: time.Second, Max: alignedhb.MaxPeriod}
	return relay
}

func newAlignedTestRelayLimits(t *testing.T, validator Validator, limits alignedhb.PeriodLimits) *Relay {
	t.Helper()
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	relay, err := NewRelay(Config{
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  validator,
		PhaseVerifier:  verifier,
		PeriodLimits:   limits,
	})
	require.NoError(t, err)
	t.Cleanup(func() { relay.Shutdown(context.Background()) })
	return relay
}

// acceptEnvelope runs the handshake for an auth envelope and returns the stored
// peer after checking the v2 response.
func acceptEnvelope(t *testing.T, relay *Relay, validator *recordingValidator, version messages.ProtocolVersion, peerID messages.PeerID, ext []byte) *Peer {
	t.Helper()
	token := []byte("future-token")
	auth, err := messages.MarshalAuthEnvelope(version, peerID, token, ext)
	require.NoError(t, err)

	conn := newScriptedConn()
	conn.deliver(t, auth)
	relay.Accept(conn)

	frames := conn.waitFrames(t, 1)
	want, err := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).AuthResponse(relay.instanceURL.String())
	require.NoError(t, err)
	assert.Equal(t, want, frames[0], "the response must carry the selected v2 header")
	assert.Equal(t, [][]byte{token}, validator.calls(), "the validator must receive the token without the extension")
	assert.False(t, conn.isClosed(), "a v2 connection must stay open")

	item, ok := relay.store.Peer(peerID)
	require.True(t, ok, "the peer must be stored after the response")
	p := item.(*Peer)
	assert.Equal(t, messages.ProtocolV2, p.Version(), "the connection must use the selected v2")
	return p
}

func TestRelay_AuthEnvelopeSelectsV2(t *testing.T) {
	// Without a signed phase a v2 connection keeps the stock health check: the
	// client has no phase from Management yet and hands it over later.
	period, err := messages.MarshalAuthExtension(messages.AuthExtension{PeriodSeconds: 90})
	require.NoError(t, err)
	unknownOnly := []byte{200, 0, 3, 'a', 'b', 'c'}

	cases := []struct {
		name    string
		version messages.ProtocolVersion
		ext     []byte
	}{
		{"v2 without extension", 2, nil},
		{"v2 with period", 2, period},
		{"v2 with unknown fields only", 2, unknownOnly},
		{"v255 with period", 255, append(append([]byte(nil), unknownOnly...), period...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &recordingValidator{}
			p := acceptEnvelope(t, newAlignedTestRelay(t, validator), validator, tc.version, messages.HashID("future-client"), tc.ext)
			assert.Nil(t, scheduleOf(p), "without a signed phase the connection must keep the stock health check")
		})
	}
}

func TestRelay_AuthSignedPhase(t *testing.T) {
	peerID := messages.HashID("aligned-client")

	t.Run("valid signature turns the schedule on", func(t *testing.T) {
		ext, sp := signedExtension(t, testPhaseSecret, peerID, 90*time.Second)
		validator := &recordingValidator{}
		p := acceptEnvelope(t, newAlignedTestRelay(t, validator), validator, messages.ProtocolV2, peerID, ext)
		require.NotNil(t, scheduleOf(p), "a phase Management signed must turn the aligned heartbeat on")
		assert.Equal(t, 90*time.Second, scheduleOf(p).Period, "period")
		assert.Equal(t, sp.Phase, scheduleOf(p).Phase, "the relay must tick on the signed phase")
	})

	t.Run("future version with unknown fields", func(t *testing.T) {
		ext, sp := signedExtension(t, testPhaseSecret, peerID, time.Minute)
		ext = append([]byte{200, 0, 1, 'x'}, ext...)
		validator := &recordingValidator{}
		p := acceptEnvelope(t, newAlignedTestRelay(t, validator), validator, 255, peerID, ext)
		require.NotNil(t, scheduleOf(p), "unknown fields must be skipped")
		assert.Equal(t, sp.Phase, scheduleOf(p).Phase, "phase")
	})

	rejected := map[string]func(t *testing.T) []byte{
		"wrong secret": func(t *testing.T) []byte {
			ext, _ := signedExtension(t, "other-secret", peerID, time.Minute)
			return ext
		},
		"phase of another peer": func(t *testing.T) []byte {
			ext, _ := signedExtension(t, testPhaseSecret, messages.HashID("other-client"), time.Minute)
			return ext
		},
		"phase picked by the client": func(t *testing.T) []byte {
			_, sp := signedExtension(t, testPhaseSecret, peerID, time.Minute)
			ext, err := messages.MarshalAuthExtension(messages.AuthExtension{
				PeriodSeconds: 60,
				SignedPhase: &messages.AuthSignedPhase{
					PhaseMs:   uint32(((sp.Phase + 5*time.Second) % time.Minute).Milliseconds()),
					Day:       sp.Day,
					Signature: sp.Signature,
				},
			})
			require.NoError(t, err)
			return ext
		},
		"signed phase without period": func(t *testing.T) []byte {
			_, sp := signedExtension(t, testPhaseSecret, peerID, time.Minute)
			ext, err := messages.MarshalAuthExtension(messages.AuthExtension{
				SignedPhase: &messages.AuthSignedPhase{
					PhaseMs:   uint32(sp.Phase.Milliseconds()),
					Day:       sp.Day,
					Signature: sp.Signature,
				},
			})
			require.NoError(t, err)
			return ext
		},
	}
	for name, ext := range rejected {
		t.Run(name, func(t *testing.T) {
			validator := &recordingValidator{}
			p := acceptEnvelope(t, newAlignedTestRelay(t, validator), validator, messages.ProtocolV2, peerID, ext(t))
			assert.Nil(t, scheduleOf(p), "a phase that does not verify must keep the stock health check, never close the connection")
		})
	}

	t.Run("relay without verifier", func(t *testing.T) {
		ext, _ := signedExtension(t, testPhaseSecret, peerID, time.Minute)
		validator := &recordingValidator{}
		p := acceptEnvelope(t, newTestRelay(t, validator), validator, messages.ProtocolV2, peerID, ext)
		assert.Nil(t, scheduleOf(p), "a relay without a secret must keep the stock health check")
	})
}

func TestRelay_AuthV1HasNoAlignedSchedule(t *testing.T) {
	relay := newTestRelay(t, &recordingValidator{})
	peerID := messages.HashID("stock-client")
	auth, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)

	conn := newScriptedConn()
	conn.deliver(t, auth)
	relay.Accept(conn)
	conn.waitFrames(t, 1)

	item, ok := relay.store.Peer(peerID)
	require.True(t, ok, "the peer must be stored")
	assert.Nil(t, scheduleOf(item.(*Peer)), "a v1 connection must keep the stock health check")
}

func TestRelay_AuthMalformedExtensionStaysStock(t *testing.T) {
	// A malformed extension is a capability problem, not an auth failure: the
	// client is accepted on v2 and keeps the stock health check.
	peerID := messages.HashID("client")
	cases := []struct {
		name string
		ext  []byte
	}{
		{"opaque bytes", []byte("opaque-extension-bytes")},
		{"truncated header", []byte{messages.ExtTypePeriod, 0}},
		{"zero period", []byte{messages.ExtTypePeriod, 0, 2, 0, 0}},
		{"period with wrong length", []byte{messages.ExtTypePeriod, 0, 3, 0, 60, 0}},
		{"valid signed phase then garbage", func() []byte {
			ext, _ := signedExtension(t, testPhaseSecret, peerID, time.Minute)
			return append(ext, messages.ExtTypePeriod, 0)
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &recordingValidator{}
			p := acceptEnvelope(t, newAlignedTestRelay(t, validator), validator, messages.ProtocolV2, peerID, tc.ext)
			assert.Nil(t, scheduleOf(p), "a malformed extension must keep the stock health check")
			assert.Equal(t, messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).Healthcheck(), healthcheckMsg(p),
				"the health check must carry no phase")
		})
	}
}

func TestRelay_AuthRejectsInvalidFirstFrame(t *testing.T) {
	peerID := messages.HashID("client")
	validEnvelope, err := messages.MarshalAuthEnvelope(2, peerID, []byte("token"), []byte("ext"))
	require.NoError(t, err)
	validV1, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)
	transportFirst, err := messages.MarshalTransportMsg(peerID, []byte("payload"))
	require.NoError(t, err)

	versionZero := append([]byte(nil), validV1...)
	versionZero[0] = 0

	badMagic := append([]byte(nil), validEnvelope...)
	badMagic[2] ^= 0xFF

	zeroTokenLen := append([]byte(nil), validEnvelope...)
	binary.BigEndian.PutUint16(zeroTokenLen[authTokenLenOffset:], 0)

	tokenLenPastEnd := append([]byte(nil), validEnvelope...)
	binary.BigEndian.PutUint16(tokenLenPastEnd[authTokenLenOffset:], uint16(len(validEnvelope)))

	cases := []struct {
		name  string
		frame []byte
	}{
		{"version zero", versionZero},
		{"reserved hello type", []byte{byte(messages.ProtocolV1), byte(messages.MsgTypeHello)}},
		{"unknown type before auth", []byte{byte(messages.ProtocolV1), 200}},
		{"transport before auth", transportFirst},
		{"bad magic in envelope", badMagic},
		{"zero token length", zeroTokenLen},
		{"token length past the frame", tokenLenPastEnd},
		{"envelope truncated at the length field", validEnvelope[:authTokenLenOffset+1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &recordingValidator{}
			relay := newTestRelay(t, validator)

			conn := newScriptedConn()
			conn.deliver(t, tc.frame)
			relay.Accept(conn)

			assert.True(t, conn.isClosed(), "the connection must be closed")
			assert.Empty(t, conn.frames(), "no response may be written")
			assert.Empty(t, validator.calls(), "the validator must not run")
			_, ok := relay.store.Peer(peerID)
			assert.False(t, ok, "the peer must not be stored")
		})
	}
}

func TestRelay_AuthRejectsInvalidToken(t *testing.T) {
	peerID := messages.HashID("client")
	v1Auth, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)
	envelopeAuth, err := messages.MarshalAuthEnvelope(2, peerID, []byte("token"), []byte(`{"ok":true}`))
	require.NoError(t, err)

	cases := []struct {
		name  string
		frame []byte
	}{
		{"v1 layout", v1Auth},
		{"envelope with extension", envelopeAuth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &recordingValidator{err: errors.New("invalid token")}
			relay := newTestRelay(t, validator)

			conn := newScriptedConn()
			conn.deliver(t, tc.frame)
			relay.Accept(conn)

			assert.True(t, conn.isClosed(), "the connection must be closed")
			assert.Empty(t, conn.frames(), "no response may be written")
			assert.Len(t, validator.calls(), 1, "the validator must run exactly once")
			_, ok := relay.store.Peer(peerID)
			assert.False(t, ok, "the peer must not be stored")
		})
	}
}

func TestRelay_AuthResponsePrecedesPublish(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	peerID := messages.HashID("client")

	onlineEvents := make(chan []messages.PeerID, 1)
	watcher := relay.notifier.NewListener(func(ids []messages.PeerID) { onlineEvents <- ids }, func([]messages.PeerID) {})
	t.Cleanup(func() { relay.notifier.RemoveListener(watcher) })
	watcher.AddInterestedPeers([]messages.PeerID{peerID})

	var storedAtResponse, notifiedAtResponse bool
	conn := newScriptedConn()
	conn.onWrite = func(frame []byte) {
		if frame[1] != byte(messages.MsgTypeAuthResponse) {
			return
		}
		_, storedAtResponse = relay.store.Peer(peerID)
		notifiedAtResponse = len(onlineEvents) > 0
	}

	auth, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)
	conn.deliver(t, auth)
	relay.Accept(conn)

	conn.waitFrames(t, 1)
	assert.False(t, storedAtResponse, "the peer must not be in the store when the response is written")
	assert.False(t, notifiedAtResponse, "no online notification may precede the response")

	select {
	case ids := <-onlineEvents:
		assert.Equal(t, []messages.PeerID{peerID}, ids, "the peer must be published after the response")
	case <-time.After(testWaitTimeout):
		t.Fatal("the peer was not published after the response")
	}
}

func TestRelay_ReconnectClosesPreviousConnection(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	first, peerID := acceptPeer(t, relay, "client")

	auth, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)
	second := newScriptedConn()
	second.deliver(t, auth)
	relay.Accept(second)

	second.waitFrames(t, 1)
	first.waitClosed(t)
	assert.False(t, second.isClosed(), "the reconnecting client must keep its new connection")
	item, ok := relay.store.Peer(peerID)
	require.True(t, ok, "the peer must stay stored after a reconnect")
	assert.Same(t, second, item.(*Peer).conn, "the store must hold the new connection")
}

func newTestRelay(t *testing.T, validator Validator) *Relay {
	t.Helper()
	relay, err := NewRelay(Config{
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  validator,
	})
	require.NoError(t, err)
	t.Cleanup(func() { relay.Shutdown(context.Background()) })
	return relay
}

func acceptPeer(t *testing.T, relay *Relay, name string) (*scriptedConn, messages.PeerID) {
	t.Helper()
	peerID := messages.HashID(name)
	auth, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)

	conn := newScriptedConn()
	conn.deliver(t, auth)
	relay.Accept(conn)
	conn.waitFrames(t, 1)
	return conn, peerID
}

// tunableConn records the heartbeat period the relay tuned its transport for.
type tunableConn struct {
	*scriptedConn
	period atomic.Int64
}

func (c *tunableConn) UseAlignedHeartbeat(period time.Duration) error {
	c.period.Store(int64(period))
	return nil
}

func (c *tunableConn) tunedPeriod() time.Duration {
	return time.Duration(c.period.Load())
}

// Only a connection with a verified signed phase tunes its transport, for the
// period of that phase. A v1 or a stock v2 connection keeps the stock transport.
func TestRelay_OnlyAlignedTunesTransport(t *testing.T) {
	peerID := messages.HashID("transport-client")
	v1, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)
	v2, err := messages.MarshalAuthEnvelope(messages.ProtocolV2, peerID, []byte("token"), nil)
	require.NoError(t, err)
	ext, _ := signedExtension(t, testPhaseSecret, peerID, 2*time.Second)
	v2Signed, err := messages.MarshalAuthEnvelope(messages.ProtocolV2, peerID, []byte("token"), ext)
	require.NoError(t, err)

	cases := []struct {
		name   string
		auth   []byte
		period time.Duration
	}{
		{"v1 keeps the stock transport", v1, 0},
		{"v2 without a signed phase keeps the stock transport", v2, 0},
		{"v2 with a signed phase tunes the transport", v2Signed, 2 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := newAlignedTestRelay(t, &recordingValidator{})
			conn := &tunableConn{scriptedConn: newScriptedConn()}
			conn.deliver(t, tc.auth)
			relay.Accept(conn)
			conn.waitFrames(t, 1)

			_, ok := relay.store.Peer(peerID)
			require.True(t, ok, "the peer must be stored")
			assert.Equal(t, tc.period, conn.tunedPeriod(), "transport tuning")
		})
	}
}
