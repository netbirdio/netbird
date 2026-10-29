package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/peerauth"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

// recordingSignalServer is a real Signal that also records the metadata of every call, as a
// verifier in front of it would see it.
type recordingSignalServer struct {
	*server.Server
	mu        sync.Mutex
	streamMD  metadata.MD
	sendMD    []metadata.MD
	sendCount chan struct{}
}

func (s *recordingSignalServer) ConnectStream(stream sigProto.SignalExchange_ConnectStreamServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	s.mu.Lock()
	s.streamMD = md
	s.mu.Unlock()
	return s.Server.ConnectStream(stream)
}

func (s *recordingSignalServer) Send(ctx context.Context, msg *sigProto.EncryptedMessage) (*sigProto.EncryptedMessage, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.sendMD = append(s.sendMD, md)
	s.mu.Unlock()
	s.sendCount <- struct{}{}
	return s.Server.Send(ctx, msg)
}

func TestAuthCredentials_NoTokenSendsNothing(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	a := authCredentials{key: priv, hostname: "signal.netbird.io"}

	pairs, err := a.metadataPairs(time.Now())
	require.NoError(t, err)
	assert.Nil(t, pairs, "without the auth token the client must call Signal as today")
}

func TestAuthCredentials_ProofIsReusedWithinTheWindow(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	a := authCredentials{key: priv, hostname: "signal.netbird.io"}
	a.update([]byte("token-1"))
	now := time.Now()

	first, err := a.metadataPairs(now)
	require.NoError(t, err)
	again, err := a.metadataPairs(now.Add(proofRefreshInterval - time.Second))
	require.NoError(t, err)
	assert.Equal(t, first, again, "a proof must be reused within the window so Signal can cache it")

	later, err := a.metadataPairs(now.Add(proofRefreshInterval))
	require.NoError(t, err)
	assert.NotEqual(t, first, later, "a proof must be renewed once the window is over")

	// NTP steps a fast clock back by an hour: the cached proof now looks signed in the future.
	steppedBack, err := a.metadataPairs(now.Add(proofRefreshInterval - time.Hour))
	require.NoError(t, err)
	assert.NotEqual(t, later, steppedBack, "a proof must be renewed when the clock steps back")

	a.update([]byte("token-2"))
	renewed, err := a.metadataPairs(now)
	require.NoError(t, err)
	assert.NotEqual(t, first, renewed, "a new token must get its own proof")
}

func TestAuthCredentials_EmptyTokenStopsPresenting(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	a := authCredentials{key: priv, hostname: "signal.netbird.io"}
	a.update([]byte("token"))

	// Management stops issuing the auth token: the client goes back to calling Signal as today.
	a.update(nil)
	pairs, err := a.metadataPairs(time.Now())
	require.NoError(t, err)
	assert.Nil(t, pairs, "no auth token must mean no credentials, never stale ones")
}

func TestAuthCredentials_TokenWithoutKeyFails(t *testing.T) {
	var a authCredentials
	a.update([]byte("token"))
	_, err := a.metadataPairs(time.Now())
	assert.Error(t, err, "an auth token cannot be presented without the key that signs its proof")
}

func TestSignalHostname(t *testing.T) {
	for addr, want := range map[string]string{
		"signal.netbird.io:443":         "signal.netbird.io",
		"https://signal.netbird.io:443": "signal.netbird.io",
		"signal.netbird.io":             "signal.netbird.io",
		"[2001:db8::1]:10000":           "2001:db8::1",
	} {
		assert.Equal(t, want, signalHostname(addr), "hostname of %q", addr)
	}
}

// The stream and every Send must carry credentials a Signal verifier accepts, for the
// hostname the client dialed.
func TestClient_PresentsAuthTokenOnStreamAndSend(t *testing.T) {
	realServer, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	recorder := &recordingSignalServer{Server: realServer, sendCount: make(chan struct{}, 8)}
	addr := serveTestSignalExchange(t, recorder)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client, err := NewClient(ctx, addr, key, false, WithAuthKey(priv))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	token := []byte("opaque auth token")
	client.UpdateAuthToken(token)

	receiveDone := make(chan struct{})
	go func() {
		defer close(receiveDone)
		_ = client.Receive(ctx, func(*sigProto.Message) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		<-receiveDone
	})

	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	client.WaitStreamConnected(waitCtx)
	require.True(t, client.StreamConnected(), "client must register its stream")

	self := key.PublicKey().String()
	require.NoError(t, client.Send(&sigProto.Message{Key: self, RemoteKey: self, Body: &sigProto.Body{Type: sigProto.Body_HEARTBEAT}}))
	select {
	case <-recorder.sendCount:
	case <-time.After(5 * time.Second):
		t.Fatal("Send never reached Signal")
	}

	recorder.mu.Lock()
	streamMD, sendMD := recorder.streamMD, recorder.sendMD[0]
	recorder.mu.Unlock()

	for name, md := range map[string]metadata.MD{"stream": streamMD, "send": sendMD} {
		gotToken, proof, err := peerauth.FromMetadata(md)
		require.NoError(t, err, "%s must carry the credentials", name)
		assert.Equal(t, token, gotToken, "%s must carry the auth token unchanged", name)
		assert.NoError(t, peerauth.VerifyProof(pub, peerauth.ServiceSignal, gotToken, proof, []string{"127.0.0.1"}, time.Now(), peerauth.DefaultSkew),
			"%s proof must verify for the dialed hostname", name)
	}
}
