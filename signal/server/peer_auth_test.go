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
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/shared/peerauth"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

var signalAuthTestSecret = sha256.Sum256([]byte("relay-secret"))

func signalAuthTestKeys() peerauth.TokenKeys {
	return peerauth.TokenKeys{HMAC: signalAuthTestSecret[:]}
}

func newPeerAuthTestSignal(t *testing.T, cfg PeerAuthConfig) *Server {
	t.Helper()
	s, err := NewServerWithPeerAuth(context.Background(), otel.Meter(""), cfg)
	require.NoError(t, err)
	t.Cleanup(s.Stop)
	return s
}

// signalPeer is a peer holding a token bound to its keys, as Management issues it.
type signalPeer struct {
	key     string
	token   []byte
	authKey ed25519.PrivateKey
}

func newSignalPeer(t *testing.T, secret []byte) signalPeer {
	t.Helper()
	wgKey, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	authPub, authKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	token, err := peerauth.IssueHMACToken(secret, peerauth.Token{
		Expiry:  time.Now().Add(time.Hour),
		WGPub:   wgKey.PublicKey(),
		AuthPub: authPub,
	})
	require.NoError(t, err)
	return signalPeer{key: wgKey.PublicKey().String(), token: token, authKey: authKey}
}

func (p signalPeer) metadata(t *testing.T, hostname string, signedAt time.Time) metadata.MD {
	t.Helper()
	proof, err := peerauth.SignProof(p.authKey, peerauth.ServiceSignal, p.token, hostname, signedAt)
	require.NoError(t, err)
	return metadata.Pairs(peerauth.MetadataPairs(p.token, proof)...)
}

func (p signalPeer) message() *proto.EncryptedMessage {
	return &proto.EncryptedMessage{Key: p.key, RemoteKey: p.key}
}

func sendWith(s *Server, md metadata.MD, msg *proto.EncryptedMessage) error {
	ctx := context.Background()
	if md != nil {
		ctx = metadata.NewIncomingContext(ctx, md)
	}
	_, err := s.Send(ctx, msg)
	return err
}

// authTestStream is a ConnectStream whose context carries the registration metadata.
type authTestStream struct {
	proto.SignalExchange_ConnectStreamServer
	ctx context.Context
}

func (s *authTestStream) Context() context.Context { return s.ctx }

func (s *authTestStream) Send(*proto.EncryptedMessage) error { return nil }

func registerWith(t *testing.T, s *Server, id string, md metadata.MD) error {
	t.Helper()
	all := metadata.Join(metadata.Pairs(proto.HeaderId, id), md)
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), all))
	t.Cleanup(cancel)
	p, err := s.RegisterPeer(&authTestStream{ctx: ctx}, cancel)
	if err == nil {
		t.Cleanup(func() { s.DeregisterPeer(p) })
	}
	return err
}

func TestSignal_AcceptsBoundCredentials(t *testing.T) {
	cases := []struct {
		name      string
		hostnames []string
		hostname  string
		signedAt  time.Time
	}{
		{"no hostname list accepts any name", nil, "any.example.com", time.Now()},
		{"listed hostname", []string{"signal.example.com", "signal-1.example.com"}, "signal-1.example.com", time.Now()},
		// Without --peer-auth-check-time the peer clock does not matter.
		{"peer clock an hour behind", nil, "signal.example.com", time.Now().Add(-time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys(), Hostnames: tc.hostnames, Required: true})
			p := newSignalPeer(t, signalAuthTestSecret[:])
			md := p.metadata(t, tc.hostname, tc.signedAt)

			require.NoError(t, registerWith(t, s, p.key, md), "stream with valid credentials must register")
			registered, found := s.registry.Get(p.key)
			require.True(t, found, "peer must be registered")
			assert.True(t, registered.Authenticated, "stream must be marked authenticated")
			assert.NoError(t, sendWith(s, md, p.message()), "send with valid credentials must pass")
		})
	}
}

func TestSignal_RefusesBadCredentials(t *testing.T) {
	other := sha256.Sum256([]byte("other-secret"))
	cases := []struct {
		name string
		md   func(t *testing.T, p signalPeer) (metadata.MD, string)
	}{
		{"partial credentials", func(t *testing.T, p signalPeer) (metadata.MD, string) {
			return metadata.Pairs(peerauth.MetadataToken, string(p.token)), p.key
		}},
		{"stale proof", func(t *testing.T, p signalPeer) (metadata.MD, string) {
			return p.metadata(t, "signal.example.com", time.Now().Add(-time.Hour)), p.key
		}},
		{"hostname not listed", func(t *testing.T, p signalPeer) (metadata.MD, string) {
			return p.metadata(t, "evil.example.com", time.Now()), p.key
		}},
		{"token bound to another peer", func(t *testing.T, p signalPeer) (metadata.MD, string) {
			return p.metadata(t, "signal.example.com", time.Now()), newSignalPeer(t, signalAuthTestSecret[:]).key
		}},
		{"token signed with another secret", func(t *testing.T, _ signalPeer) (metadata.MD, string) {
			forged := newSignalPeer(t, other[:])
			return forged.metadata(t, "signal.example.com", time.Now()), forged.key
		}},
		{"proof signed by another auth key", func(t *testing.T, p signalPeer) (metadata.MD, string) {
			_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			p.authKey = wrongKey
			return p.metadata(t, "signal.example.com", time.Now()), p.key
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Not required: presented credentials are still verified and never downgraded to legacy.
			s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys(), Hostnames: []string{"signal.example.com"}, CheckTime: true})
			md, key := tc.md(t, newSignalPeer(t, signalAuthTestSecret[:]))

			err := registerWith(t, s, key, md)
			assert.Equal(t, codes.Unauthenticated, status.Code(err), "stream must be refused, got %v", err)
			assert.False(t, s.registry.IsPeerRegistered(key), "refused stream must not register")

			err = sendWith(s, md, &proto.EncryptedMessage{Key: key, RemoteKey: key})
			assert.Equal(t, codes.Unauthenticated, status.Code(err), "send must be refused, got %v", err)
		})
	}
}

func TestSignal_LegacyPeers(t *testing.T) {
	legacy := newSignalPeer(t, signalAuthTestSecret[:])

	t.Run("accepted when not required", func(t *testing.T) {
		s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys()})
		require.NoError(t, registerWith(t, s, legacy.key, nil))
		assert.NoError(t, sendWith(s, nil, legacy.message()))
	})

	t.Run("refused when required", func(t *testing.T) {
		s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys(), Required: true})
		assert.Equal(t, codes.Unauthenticated, status.Code(registerWith(t, s, legacy.key, nil)), "legacy stream must be refused")
		assert.Equal(t, codes.Unauthenticated, status.Code(sendWith(s, nil, legacy.message())), "legacy send must be refused")
	})

	t.Run("credentials ignored without keys", func(t *testing.T) {
		// A Signal without keys behaves as today, whatever a new client presents.
		s := newPeerAuthTestSignal(t, PeerAuthConfig{})
		p := newSignalPeer(t, signalAuthTestSecret[:])
		md := p.metadata(t, "signal.example.com", time.Now().Add(-time.Hour))
		require.NoError(t, registerWith(t, s, p.key, md))
		registered, _ := s.registry.Get(p.key)
		assert.False(t, registered.Authenticated, "without keys no stream is authenticated")
		assert.NoError(t, sendWith(s, md, p.message()))
	})

	t.Run("required without keys fails at startup", func(t *testing.T) {
		_, err := NewServerWithPeerAuth(context.Background(), otel.Meter(""), PeerAuthConfig{Required: true})
		assert.Error(t, err, "requiring credentials Signal cannot verify must not start")
	})
}

func TestSignal_LegacyCannotTakeOverAuthenticatedPeer(t *testing.T) {
	s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys()})
	p := newSignalPeer(t, signalAuthTestSecret[:])
	md := p.metadata(t, "signal.example.com", time.Now())
	require.NoError(t, registerWith(t, s, p.key, md))

	assert.Equal(t, codes.PermissionDenied, status.Code(registerWith(t, s, p.key, nil)),
		"a legacy stream must not replace an authenticated one")
	assert.Equal(t, codes.PermissionDenied, status.Code(sendWith(s, nil, p.message())),
		"a legacy send must not speak for an authenticated peer")

	// The peer itself reconnecting with credentials still replaces its stream.
	assert.NoError(t, registerWith(t, s, p.key, p.metadata(t, "signal.example.com", time.Now())))
}

func TestSignal_AuthenticatedReplacesLegacyPeer(t *testing.T) {
	s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys()})
	p := newSignalPeer(t, signalAuthTestSecret[:])
	require.NoError(t, registerWith(t, s, p.key, nil))

	require.NoError(t, registerWith(t, s, p.key, p.metadata(t, "signal.example.com", time.Now())),
		"the real peer must be able to replace a legacy stream holding its key")
	registered, _ := s.registry.Get(p.key)
	assert.True(t, registered.Authenticated, "the registered stream must be the authenticated one")
}

func TestSignal_ProofCache(t *testing.T) {
	s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys()})
	p := newSignalPeer(t, signalAuthTestSecret[:])
	md := p.metadata(t, "signal.example.com", time.Now())
	require.NoError(t, sendWith(s, md, p.message()))

	// From here on any full verification fails, so only a cache hit can pass.
	s.peerAuth.verifier.Keys = peerauth.TokenKeys{HMAC: make([]byte, sha256.Size)}

	assert.NoError(t, sendWith(s, md, p.message()), "the same credentials must be served from the cache")

	renewed := p.metadata(t, "signal.example.com", time.Now().Add(time.Second))
	assert.Error(t, sendWith(s, renewed, p.message()), "a new proof must be verified")

	// The cached proof with another token of the same peer is not what was verified.
	swapped := md.Copy()
	swapped.Set(peerauth.MetadataToken, string(newSignalPeer(t, signalAuthTestSecret[:]).token))
	assert.Error(t, sendWith(s, swapped, p.message()), "a cached proof must not vouch for another token")

	other := newSignalPeer(t, signalAuthTestSecret[:])
	assert.Error(t, sendWith(s, md, other.message()), "cached credentials must not vouch for another peer key")
}

// A verified proof stays cached as long as it would verify again: until the token expires, or,
// with the timestamp check, until the proof leaves the skew if that comes first.
func TestSignal_ProofCacheExpiry(t *testing.T) {
	signedAt := time.Now().Truncate(time.Second)
	for name, tc := range map[string]struct {
		checkTime bool
		want      func(tokenExpiry time.Time) time.Time
	}{
		"without time check": {false, func(tokenExpiry time.Time) time.Time { return tokenExpiry }},
		"with time check":    {true, func(time.Time) time.Time { return signedAt.Add(peerauth.DefaultSkew) }},
	} {
		t.Run(name, func(t *testing.T) {
			s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys(), CheckTime: tc.checkTime})
			p := newSignalPeer(t, signalAuthTestSecret[:])
			require.NoError(t, sendWith(s, p.metadata(t, "signal.example.com", signedAt), p.message()))

			tok, err := peerauth.VerifyToken(p.token, signalAuthTestKeys(), time.Now())
			require.NoError(t, err)
			s.peerAuth.cache.mu.Lock()
			entry, ok := s.peerAuth.cache.entries[p.key]
			s.peerAuth.cache.mu.Unlock()
			require.True(t, ok, "the verified proof must be cached")
			assert.Equal(t, tc.want(tok.Expiry), entry.expiry, "cache expiry")
		})
	}
}

func TestProofCache_ExpiresAndSweeps(t *testing.T) {
	c := newProofCache()
	digest := sha256.Sum256([]byte("credentials"))
	now := time.Now()
	c.store("peer-a", digest, now.Add(time.Minute))
	c.store("peer-b", digest, now.Add(time.Hour))

	assert.True(t, c.valid("peer-a", digest, now), "entry must be valid before expiry")
	assert.False(t, c.valid("peer-a", digest, now.Add(time.Minute)), "entry must not be valid at expiry")

	c.sweep(now.Add(time.Minute))
	c.mu.Lock()
	_, aKept := c.entries["peer-a"]
	_, bKept := c.entries["peer-b"]
	c.mu.Unlock()
	assert.False(t, aKept, "sweep must drop expired entries")
	assert.True(t, bKept, "sweep must keep live entries")

	newer := sha256.Sum256([]byte("newer credentials"))
	c.store("peer-b", newer, now.Add(time.Hour))
	assert.False(t, c.valid("peer-b", digest, now), "a newer proof must replace the older one")
	assert.True(t, c.valid("peer-b", newer, now), "the newer proof must be cached")
}

func TestSignal_RefusalLogLevels(t *testing.T) {
	// Refusals a peer repeats on every retry stay at debug; credentials that do not verify, or a
	// legacy call claiming an authenticated peer, are rare and logged at info.
	other := sha256.Sum256([]byte("other-secret"))
	cases := []struct {
		name     string
		required bool
		register func(t *testing.T, s *Server) error
		level    log.Level
	}{
		{"legacy peer when required", true, func(t *testing.T, s *Server) error {
			return registerWith(t, s, newSignalPeer(t, signalAuthTestSecret[:]).key, nil)
		}, log.DebugLevel},
		{"forged token", false, func(t *testing.T, s *Server) error {
			forged := newSignalPeer(t, other[:])
			return registerWith(t, s, forged.key, forged.metadata(t, "signal.example.com", time.Now()))
		}, log.InfoLevel},
		{"stale proof", false, func(t *testing.T, s *Server) error {
			p := newSignalPeer(t, signalAuthTestSecret[:])
			return registerWith(t, s, p.key, p.metadata(t, "signal.example.com", time.Now().Add(-time.Hour)))
		}, log.InfoLevel},
		{"legacy takeover", false, func(t *testing.T, s *Server) error {
			p := newSignalPeer(t, signalAuthTestSecret[:])
			require.NoError(t, registerWith(t, s, p.key, p.metadata(t, "signal.example.com", time.Now())))
			return registerWith(t, s, p.key, nil)
		}, log.InfoLevel},
	}
	prevLevel := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetLevel(prevLevel) })
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newPeerAuthTestSignal(t, PeerAuthConfig{Keys: signalAuthTestKeys(), Required: tc.required, CheckTime: true})
			hook.Reset()
			require.Error(t, tc.register(t, s))

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
