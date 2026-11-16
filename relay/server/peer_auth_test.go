package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/shared/peerauth"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// peerAuthTestMgmtKey is the Management signing key the test Relays trust.
func peerAuthTestMgmtKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("relay-test-management-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func newPeerAuthTestRelay(t *testing.T, validator Validator, cfg PeerAuthConfig) *Relay {
	t.Helper()
	keys, err := peerauth.NewEd25519Keys([]ed25519.PublicKey{peerAuthTestMgmtKey().Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	cfg.Keys = keys
	relay, err := NewRelay(Config{
		ExposedAddress: "rels://relay-1.example.com:443",
		AuthValidator:  validator,
		PeerAuth:       cfg,
	})
	require.NoError(t, err)
	t.Cleanup(func() { relay.Shutdown(context.Background()) })
	return relay
}

// boundPeer is a peer holding a token bound to its keys, as Management issues it.
type boundPeer struct {
	id      messages.PeerID
	token   []byte
	authKey ed25519.PrivateKey
}

func newBoundPeer(t *testing.T) boundPeer {
	t.Helper()
	wgKey, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	authPub, authKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	token, err := peerauth.IssueEd25519Token(peerAuthTestMgmtKey(), peerauth.Token{
		Expiry:  time.Now().Add(time.Hour),
		WGPub:   wgKey.PublicKey(),
		AuthPub: authPub,
	})
	require.NoError(t, err)
	return boundPeer{id: messages.HashID(wgKey.PublicKey().String()), token: token, authKey: authKey}
}

func (p boundPeer) authMsg(t *testing.T, id messages.PeerID, hostname string, signedAt time.Time) []byte {
	t.Helper()
	proof, err := peerauth.SignProof(p.authKey, peerauth.ServiceRelay, p.token, hostname, signedAt)
	require.NoError(t, err)
	ext, err := peerauth.MarshalRelayExtension(proof)
	require.NoError(t, err)
	msg, err := messages.MarshalAuthEnvelope(messages.ProtocolV2, id, p.token, ext)
	require.NoError(t, err)
	return msg
}

func TestRelay_AcceptsBoundTokenWithProof(t *testing.T) {
	cases := []struct {
		name      string
		hostnames []string
		hostname  string
		signedAt  time.Time
	}{
		{"no hostname list accepts any name", nil, "any.example.com", time.Now()},
		{"listed exposed address", []string{"relay-1.example.com", "relay.example.com"}, "relay-1.example.com", time.Now()},
		{"listed global name", []string{"relay-1.example.com", "relay.example.com"}, "relay.example.com", time.Now()},
		// Without --peer-auth-check-time the peer clock does not matter.
		{"peer clock an hour behind", nil, "relay.example.com", time.Now().Add(-time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &recordingValidator{}
			relay := newPeerAuthTestRelay(t, validator, PeerAuthConfig{Hostnames: tc.hostnames})
			peer := newBoundPeer(t)

			conn := newScriptedConn()
			conn.deliver(t, peer.authMsg(t, peer.id, tc.hostname, tc.signedAt))
			relay.Accept(conn)

			frames := conn.waitFrames(t, 1)
			want, err := messages.NewEncoder(messages.ProtocolV2).AuthResponse(relay.instanceURL.String())
			require.NoError(t, err)
			assert.Equal(t, want, frames[0], "an authenticated peer must get the v2 response")
			assert.Empty(t, validator.calls(), "a bound token must not reach the legacy validator")

			item, ok := relay.store.Peer(peer.id)
			require.True(t, ok, "the authenticated peer must be stored")
			assert.True(t, item.(*Peer).Authenticated(), "the peer must be marked authenticated")
			assert.Equal(t, messages.ProtocolV2, item.(*Peer).Version(), "the connection must use v2")
		})
	}
}

// Once hostnames are listed, only those are accepted: the exposed address is not added implicitly.
func TestRelay_HostnameListIsExhaustive(t *testing.T) {
	for _, hostname := range []string{"evil.example.com", "relay-1.example.com"} {
		t.Run(hostname, func(t *testing.T) {
			relay := newPeerAuthTestRelay(t, &recordingValidator{}, PeerAuthConfig{Hostnames: []string{"relay.example.com"}})
			peer := newBoundPeer(t)

			conn := newScriptedConn()
			conn.deliver(t, peer.authMsg(t, peer.id, hostname, time.Now()))
			relay.Accept(conn)

			assert.True(t, conn.isClosed(), "a proof for an unlisted hostname must be refused")
			assert.Empty(t, relay.store.Peers(), "no peer may be stored")
		})
	}
}

func TestRelay_RefusesBadBoundCredentials(t *testing.T) {
	peer := newBoundPeer(t)
	other := newBoundPeer(t)
	malformedExt, err := messages.MarshalAuthEnvelope(messages.ProtocolV2, peer.id, peer.token, []byte{1, 0, 200})
	require.NoError(t, err)

	cases := []struct {
		name  string
		frame []byte
	}{
		{"stale proof", peer.authMsg(t, peer.id, "relay-1.example.com", time.Now().Add(-time.Hour))},
		{"token of another peer", peer.authMsg(t, other.id, "relay-1.example.com", time.Now())},
		{"malformed extension", malformedExt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &recordingValidator{}
			relay := newPeerAuthTestRelay(t, validator, PeerAuthConfig{CheckTime: true})

			conn := newScriptedConn()
			conn.deliver(t, tc.frame)
			relay.Accept(conn)

			assert.True(t, conn.isClosed(), "the connection must be closed")
			assert.Empty(t, conn.frames(), "no response may be written")
			assert.Empty(t, validator.calls(), "presented credentials must never fall back to the legacy validator")
			assert.Empty(t, relay.store.Peers(), "no peer may be stored")
		})
	}
}

// A bound token reaching a Relay without Management's public keys means the operator enabled the
// signing key on Management before configuring the Relay: the refusal names the misconfiguration.
func TestRelay_RefusesBoundTokenWithoutKeys(t *testing.T) {
	validator := &recordingValidator{}
	relay := newTestRelay(t, validator)
	peer := newBoundPeer(t)
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)

	// Every peer retries, so the error is logged once per interval, not once per attempt.
	for range 3 {
		conn := newScriptedConn()
		conn.deliver(t, peer.authMsg(t, peer.id, "127.0.0.1", time.Now()))
		relay.Accept(conn)
		assert.True(t, conn.isClosed(), "a relay without peer auth keys must refuse a bound token")
	}

	assert.Empty(t, validator.calls(), "the bound token must not reach the legacy validator")
	var refusals []*log.Entry
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "refused") && e.Level == log.ErrorLevel {
			refusals = append(refusals, e)
		}
	}
	require.Len(t, refusals, 1, "a missing key is an operator error, logged once per interval")
	assert.Contains(t, refusals[0].Message, "--peer-auth-public-keys", "the refusal must name the missing configuration")
}

func TestRelay_PeerAuthRequiredWithoutKeysFailsStartup(t *testing.T) {
	_, err := NewRelay(Config{
		ExposedAddress: "rels://relay-1.example.com:443",
		AuthValidator:  &recordingValidator{},
		PeerAuth:       PeerAuthConfig{Required: true},
	})
	assert.Error(t, err, "a relay requiring peer auth without keys would refuse every peer")
}

// After the flag day the relay runs without the auth secret: legacy peers are refused and bound
// tokens are the only way in. Without the requirement there would be nothing to check legacy
// tokens with, so startup fails.
func TestRelay_FlagDayWithoutValidator(t *testing.T) {
	_, err := NewRelay(Config{ExposedAddress: "rels://relay-1.example.com:443"})
	assert.Error(t, err, "a relay without a validator must require peer auth")

	relay := newPeerAuthTestRelay(t, nil, PeerAuthConfig{Required: true})

	legacy, err := messages.MarshalAuthMsg(messages.HashID("legacy"), []byte("legacy-token"))
	require.NoError(t, err)
	legacyConn := newScriptedConn()
	legacyConn.deliver(t, legacy)
	relay.Accept(legacyConn)
	assert.True(t, legacyConn.isClosed(), "a legacy peer must be refused")

	peer := newBoundPeer(t)
	conn := newScriptedConn()
	conn.deliver(t, peer.authMsg(t, peer.id, "relay-1.example.com", time.Now()))
	relay.Accept(conn)
	conn.waitFrames(t, 1)
	_, ok := relay.store.Peer(peer.id)
	assert.True(t, ok, "a peer with a bound token must be accepted")
}

func TestRelay_PeerAuthRequiredRefusesLegacy(t *testing.T) {
	validator := &recordingValidator{}
	relay := newPeerAuthTestRelay(t, validator, PeerAuthConfig{Required: true})
	legacyID := messages.HashID("legacy")
	auth, err := messages.MarshalAuthMsg(legacyID, []byte("legacy-token"))
	require.NoError(t, err)

	conn := newScriptedConn()
	conn.deliver(t, auth)
	relay.Accept(conn)

	assert.True(t, conn.isClosed(), "a required relay must refuse a legacy peer")
	assert.Empty(t, validator.calls(), "the legacy token must not even be checked")

	peer := newBoundPeer(t)
	authConn := newScriptedConn()
	authConn.deliver(t, peer.authMsg(t, peer.id, "relay-1.example.com", time.Now()))
	relay.Accept(authConn)
	authConn.waitFrames(t, 1)
	_, ok := relay.store.Peer(peer.id)
	assert.True(t, ok, "a required relay must still accept a bound token")
}

// Knowing a peer ID is enough to present a legacy token for it, so a legacy connection must not
// take over the ID of an authenticated peer.
func TestRelay_LegacyCannotTakeOverAuthenticatedPeer(t *testing.T) {
	relay := newPeerAuthTestRelay(t, &recordingValidator{}, PeerAuthConfig{})
	peer := newBoundPeer(t)

	authConn := newScriptedConn()
	authConn.deliver(t, peer.authMsg(t, peer.id, "relay-1.example.com", time.Now()))
	relay.Accept(authConn)
	authConn.waitFrames(t, 1)

	legacyAuth, err := messages.MarshalAuthMsg(peer.id, []byte("legacy-token"))
	require.NoError(t, err)
	legacyConn := newScriptedConn()
	legacyConn.deliver(t, legacyAuth)
	relay.Accept(legacyConn)

	assert.True(t, legacyConn.isClosed(), "the legacy connection must be refused")
	assert.Empty(t, legacyConn.frames(), "the refused connection must not be told the handshake succeeded")
	assert.False(t, authConn.isClosed(), "the authenticated connection must stay open")
	item, ok := relay.store.Peer(peer.id)
	require.True(t, ok)
	assert.True(t, item.(*Peer).Authenticated(), "the stored peer must still be the authenticated one")
}

// With Management's public keys configured, the Relay accepts tokens of every listed key, so a
// rotation does not cut off peers holding a token of the old key, and refuses HMAC tokens, so the
// auth secret it keeps for legacy peers cannot be used to mint bound tokens.
func TestRelay_Ed25519Keys(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keys, err := peerauth.NewEd25519Keys([]ed25519.PublicKey{oldPub, newPub})
	require.NoError(t, err)

	issueEd25519 := func(priv ed25519.PrivateKey) func(peerauth.Token) ([]byte, error) {
		return func(tok peerauth.Token) ([]byte, error) { return peerauth.IssueEd25519Token(priv, tok) }
	}
	// A token of the right size that names another algorithm, as a secret holder would forge one: only
	// the algorithm byte differs from a valid token, so the algorithm check alone refuses it.
	issueHMAC := func(tok peerauth.Token) ([]byte, error) {
		signed, err := peerauth.IssueEd25519Token(oldPriv, tok)
		if err != nil {
			return nil, err
		}
		signed[0] = 1
		return signed, nil
	}

	cases := []struct {
		name     string
		issue    func(peerauth.Token) ([]byte, error)
		accepted bool
	}{
		{"token of the old key", issueEd25519(oldPriv), true},
		{"token of the new key", issueEd25519(newPriv), true},
		{"HMAC token", issueHMAC, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay, err := NewRelay(Config{
				ExposedAddress: "rels://relay-1.example.com:443",
				AuthValidator:  &recordingValidator{},
				PeerAuth:       PeerAuthConfig{Keys: keys},
			})
			require.NoError(t, err)
			t.Cleanup(func() { relay.Shutdown(context.Background()) })

			peer := newBoundPeer(t)
			wgKey, err := wgtypes.GenerateKey()
			require.NoError(t, err)
			peer.id = messages.HashID(wgKey.PublicKey().String())
			peer.token, err = tc.issue(peerauth.Token{
				Expiry:  time.Now().Add(time.Hour),
				WGPub:   wgKey.PublicKey(),
				AuthPub: peer.authKey.Public().(ed25519.PublicKey),
			})
			require.NoError(t, err)

			conn := newScriptedConn()
			conn.deliver(t, peer.authMsg(t, peer.id, "relay-1.example.com", time.Now()))
			relay.Accept(conn)

			if !tc.accepted {
				assert.True(t, conn.isClosed(), "the connection must be refused")
				assert.Empty(t, relay.store.Peers(), "no peer may be stored")
				return
			}
			conn.waitFrames(t, 1)
			item, ok := relay.store.Peer(peer.id)
			require.True(t, ok, "the peer must be stored")
			assert.True(t, item.(*Peer).Authenticated(), "the peer must be marked authenticated")
		})
	}
}

func TestRelay_RefusalLogLevels(t *testing.T) {
	// Refusals a peer repeats on every retry stay at debug; credentials that do not verify, or a
	// legacy connection claiming an authenticated peer, are rare and logged at info.
	legacyMsg := func(t *testing.T, id messages.PeerID) []byte {
		msg, err := messages.MarshalAuthMsg(id, []byte("legacy-token"))
		require.NoError(t, err)
		return msg
	}
	cases := []struct {
		name     string
		required bool
		frame    func(t *testing.T, relay *Relay) []byte
		level    log.Level
	}{
		{"legacy peer when required", true, func(t *testing.T, _ *Relay) []byte {
			return legacyMsg(t, messages.HashID("legacy"))
		}, log.DebugLevel},
		{"token of another peer", false, func(t *testing.T, _ *Relay) []byte {
			return newBoundPeer(t).authMsg(t, newBoundPeer(t).id, "relay-1.example.com", time.Now())
		}, log.InfoLevel},
		{"stale proof", false, func(t *testing.T, _ *Relay) []byte {
			p := newBoundPeer(t)
			return p.authMsg(t, p.id, "relay-1.example.com", time.Now().Add(-time.Hour))
		}, log.InfoLevel},
		{"legacy takeover", false, func(t *testing.T, relay *Relay) []byte {
			p := newBoundPeer(t)
			authConn := newScriptedConn()
			authConn.deliver(t, p.authMsg(t, p.id, "relay-1.example.com", time.Now()))
			relay.Accept(authConn)
			authConn.waitFrames(t, 1)
			return legacyMsg(t, p.id)
		}, log.InfoLevel},
	}
	prevLevel := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetLevel(prevLevel) })
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := newPeerAuthTestRelay(t, &recordingValidator{}, PeerAuthConfig{Required: tc.required, CheckTime: true})
			frame := tc.frame(t, relay)
			hook.Reset()

			conn := newScriptedConn()
			conn.deliver(t, frame)
			relay.Accept(conn)
			require.True(t, conn.isClosed(), "the connection must be refused")

			var refusals []*log.Entry
			for _, e := range hook.AllEntries() {
				if strings.Contains(e.Message, "refused") {
					refusals = append(refusals, e)
				}
			}
			require.Len(t, refusals, 1, "exactly one refusal must be logged")
			assert.Equal(t, tc.level, refusals[0].Level, "refusal level, message %q", refusals[0].Message)
		})
	}
}
