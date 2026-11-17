package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func askAligned(period time.Duration) func() (time.Duration, bool) {
	return func() (time.Duration, bool) { return period, true }
}

func tokenStore(t *testing.T) *hmac.TokenStore {
	t.Helper()
	store := &hmac.TokenStore{}
	require.NoError(t, store.UpdateToken(&hmac.Token{Payload: "payload", Signature: "c2ln"}))
	return store
}

// An aligned client and a stock client on the same new relay: the aligned one
// gets v2 with its period, the stock one stays v1, and traffic flows both ways.
func TestAlignedClientWithStockPeer(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeWS))
	alice := runAlignedWithStockPeer(t, "127.0.0.1:50911")
	assert.Equal(t, "ws", alice.Transport(), "transport")
}

func runAlignedWithStockPeer(t *testing.T, addr string) *Client {
	t.Helper()
	ctx := context.Background()
	serverCfg := newClientTestServerConfig(addr)
	srv, err := server.NewServer(serverCfg)
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: addr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown(ctx) })
	require.NoError(t, waitForServerToStart(errChan))

	alice := NewClient(serverCfg.ExposedAddress, tokenStore(t), "alice", iface.DefaultMTU)
	alice.alignedRequest = askAligned(60 * time.Second)
	require.NoError(t, alice.Connect(ctx))
	t.Cleanup(func() { _ = alice.Close() })

	bob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	require.NoError(t, bob.Connect(ctx))
	t.Cleanup(func() { _ = bob.Close() })

	assert.Equal(t, messages.ProtocolV2, alice.enc.Version(), "the aligned client must get v2")
	assert.Equal(t, 60*time.Second, alice.alignedPeriod, "the aligned client must keep its period")
	assert.Equal(t, messages.ProtocolV1, bob.enc.Version(), "the stock client must stay on v1")
	assert.Zero(t, bob.alignedPeriod, "the stock client has no aligned period")

	aliceToBob, err := alice.OpenConn(ctx, "bob")
	require.NoError(t, err)
	bobToAlice, err := bob.OpenConn(ctx, "alice")
	require.NoError(t, err)

	buf := make([]byte, 1500)
	_, err = aliceToBob.Write([]byte("from alice"))
	require.NoError(t, err)
	n, err := bobToAlice.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "from alice", string(buf[:n]))

	_, err = bobToAlice.Write([]byte("from bob"))
	require.NoError(t, err)
	n, err = aliceToBob.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "from bob", string(buf[:n]))
	return alice
}

// fakeRelay answers the first frame on conn with resp and reports the frame.
func fakeRelay(t *testing.T, conn net.Conn, resp []byte) <-chan []byte {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, messages.MaxHandshakeSize)
		n, err := conn.Read(buf)
		if err != nil {
			close(got)
			return
		}
		got <- append([]byte(nil), buf[:n]...)
		_, _ = conn.Write(resp)
	}()
	return got
}

func handshakeAgainst(t *testing.T, store *hmac.TokenStore, request func() (time.Duration, bool), resp []byte) (*Client, []byte, error) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	})
	c := NewClient("rel://127.0.0.1:1", store, "alice", iface.DefaultMTU)
	c.alignedRequest = request
	c.relayConn = clientSide
	got := fakeRelay(t, serverSide, resp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.handShake(ctx, messages.CurrentProtocolVersion)
	// Unblocks the fake relay when the handshake failed before writing.
	_ = clientSide.Close()
	return c, <-got, err
}

// A relay that only knows v1 answers a v2 auth with a v1 response. The client
// then runs stock on v1, with no aligned period.
func TestAlignedClientOnV1Relay(t *testing.T) {
	resp, err := messages.MarshalAuthResponse("rel://relay")
	require.NoError(t, err)
	c, auth, err := handshakeAgainst(t, tokenStore(t), askAligned(60*time.Second), resp)
	require.NoError(t, err)

	version, err := messages.ReadVersion(auth)
	require.NoError(t, err)
	assert.Equal(t, messages.ProtocolV2, version, "the aligned client must advertise v2")
	raw, err := messages.AuthMsgExtension(auth)
	require.NoError(t, err)
	ext, err := messages.UnmarshalAuthExtension(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(60), ext.PeriodSeconds, "the auth must carry the period")

	assert.Equal(t, messages.ProtocolV1, c.enc.Version(), "the client must follow the selected v1")
	assert.Zero(t, c.alignedPeriod, "v1 must leave the aligned heartbeat off")
}

func TestStockClientSendsV1Auth(t *testing.T) {
	resp, err := messages.MarshalAuthResponse("rel://relay")
	require.NoError(t, err)
	store := tokenStore(t)
	c, auth, err := handshakeAgainst(t, store, func() (time.Duration, bool) { return 0, false }, resp)
	require.NoError(t, err)

	want, err := messages.MarshalAuthMsg(c.hashedID, store.TokenBinary())
	require.NoError(t, err)
	assert.Equal(t, want, auth, "a stock client must send the v1 auth unchanged")
	assert.Equal(t, messages.ProtocolV1, c.enc.Version())
	assert.Zero(t, c.alignedPeriod)
}

func TestClientRejectsVersionAboveAdvertised(t *testing.T) {
	resp, err := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).AuthResponse("rel://relay")
	require.NoError(t, err)
	_, _, err = handshakeAgainst(t, tokenStore(t), func() (time.Duration, bool) { return 0, false }, resp)
	assert.ErrorIs(t, err, messages.ErrUnsupportedVersion, "a v1 client must reject a v2 response")
}

func TestAlignedClientWithoutTokenSendsV1(t *testing.T) {
	resp, err := messages.MarshalAuthResponse("rel://relay")
	require.NoError(t, err)
	c, auth, err := handshakeAgainst(t, &hmac.TokenStore{}, askAligned(60*time.Second), resp)
	require.NoError(t, err)
	assert.Equal(t, byte(messages.ProtocolV1), auth[0], "the envelope cannot carry an empty token")
	assert.Zero(t, c.alignedPeriod)
}

// Once Management signed a phase, the auth carries it with the period it was
// signed for, which wins over the period the client asks for.
func TestAlignedClientSendsSignedPhase(t *testing.T) {
	peer := messages.HashID("alice")
	sp := alignedhb.SignedPhase{Phase: 4321 * time.Millisecond, Day: 20405, Signature: []byte{1, 2, 3, 4}}
	alignedhb.StoreSignedPhase(peer, 120*time.Second, sp)
	t.Cleanup(func() { alignedhb.ClearSignedPhase(peer) })

	resp, err := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).AuthResponse("rel://relay")
	require.NoError(t, err)
	c, auth, err := handshakeAgainst(t, tokenStore(t), askAligned(60*time.Second), resp)
	require.NoError(t, err)

	raw, err := messages.AuthMsgExtension(auth)
	require.NoError(t, err)
	ext, err := messages.UnmarshalAuthExtension(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(120), ext.PeriodSeconds, "the auth must carry the signed period")
	require.NotNil(t, ext.SignedPhase, "the auth must carry the signed phase")
	assert.Equal(t, messages.AuthSignedPhase{PhaseMs: 4321, Day: 20405, Signature: []byte{1, 2, 3, 4}}, *ext.SignedPhase)
	assert.Equal(t, 120*time.Second, c.alignedPeriod, "the receiver must wait for the signed period")
}

// A phase stored for another peer, as after an account switch, is not sent.
func TestAlignedClientSkipsPhaseOfOtherPeer(t *testing.T) {
	other := messages.HashID("bob")
	alignedhb.StoreSignedPhase(other, time.Minute, alignedhb.SignedPhase{Phase: time.Second, Signature: []byte{1}})
	t.Cleanup(func() { alignedhb.ClearSignedPhase(other) })

	resp, err := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).AuthResponse("rel://relay")
	require.NoError(t, err)
	_, auth, err := handshakeAgainst(t, tokenStore(t), askAligned(60*time.Second), resp)
	require.NoError(t, err)

	raw, err := messages.AuthMsgExtension(auth)
	require.NoError(t, err)
	ext, err := messages.UnmarshalAuthExtension(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(60), ext.PeriodSeconds, "period")
	assert.Nil(t, ext.SignedPhase, "the phase of another peer must not be sent")
}
