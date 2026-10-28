package peerauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/metadata"
)

type fixture struct {
	mgmtPriv ed25519.PrivateKey
	secret   []byte
	authPriv ed25519.PrivateKey
	wg       wgtypes.Key
	token    []byte
	verifier *Verifier
	now      time.Time
}

func newFixture(t *testing.T, svc Service) *fixture {
	t.Helper()
	return newFixtureWithAlgo(t, svc, AlgoEd25519)
}

func newFixtureWithAlgo(t *testing.T, svc Service, algo Algo) *fixture {
	t.Helper()
	mgmtPub, mgmtPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wgPriv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	secret := []byte("relay-and-signal-shared-secret-32")

	now := time.Unix(1_800_000_000, 0)
	content := Token{KeyID: 7, Expiry: now.Add(time.Hour), WGPub: wgPriv.PublicKey(), AuthPub: authPub}
	f := &fixture{
		mgmtPriv: mgmtPriv,
		secret:   secret,
		authPriv: authPriv,
		wg:       wgPriv.PublicKey(),
		now:      now,
		verifier: &Verifier{Service: svc, Hostnames: []string{"relay.netbird.io", "eu-1.relay.netbird.io"}},
	}
	if algo == AlgoHMACSHA256 {
		f.token, err = IssueHMACToken(secret, content)
		f.verifier.Keys = TokenKeys{HMAC: map[KeyID][]byte{7: secret}}
	} else {
		f.token, err = IssueEd25519Token(mgmtPriv, content)
		f.verifier.Keys = TokenKeys{Ed25519: map[KeyID]ed25519.PublicKey{7: mgmtPub}}
	}
	require.NoError(t, err)
	return f
}

func TestVerify_RelayRoundTrip(t *testing.T) {
	f := newFixture(t, ServiceRelay)

	p, err := SignProof(f.authPriv, ServiceRelay, f.token, "EU-1.Relay.NetBird.io.", f.now)
	require.NoError(t, err)
	ext, err := MarshalRelayExtension(p)
	require.NoError(t, err)

	// An unknown entry ahead of the proof must be skipped, as a newer client may add one.
	ext = append([]byte{0x7f, 0x00, 0x02, 0xaa, 0xbb}, ext...)
	got, err := UnmarshalRelayExtension(ext)
	require.NoError(t, err)

	tok, err := f.verifier.Verify(f.token, got, f.now.Add(30*time.Second))
	require.NoError(t, err)
	assert.Equal(t, f.wg, tok.WGPub, "token must carry the WireGuard key it was issued for")
	assert.Equal(t, KeyID(7), tok.KeyID, "token must carry the issuing key id")
}

func TestVerify_SignalMetadataRoundTrip(t *testing.T) {
	f := newFixture(t, ServiceSignal)

	p, err := SignProof(f.authPriv, ServiceSignal, f.token, "relay.netbird.io", f.now)
	require.NoError(t, err)
	md := metadata.Pairs(MetadataPairs(f.token, p)...)

	token, got, err := FromMetadata(md)
	require.NoError(t, err)
	_, err = f.verifier.Verify(token, got, f.now)
	assert.NoError(t, err)
}

func TestVerify_Rejects(t *testing.T) {
	f := newFixture(t, ServiceRelay)
	sign := func(svc Service, token []byte, host string, ts time.Time) Proof {
		p, err := SignProof(f.authPriv, svc, token, host, ts)
		require.NoError(t, err)
		return p
	}
	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	foreign, err := IssueEd25519Token(otherPriv, Token{KeyID: 7, Expiry: f.now.Add(time.Hour), WGPub: f.wg, AuthPub: otherPub})
	require.NoError(t, err)
	tampered := append([]byte(nil), f.token...)
	tampered[len(tampered)-1] ^= 1
	unknownKey := append([]byte(nil), f.token...)
	unknownKey[1+ed25519.SignatureSize+3] = 9

	tests := []struct {
		name  string
		token []byte
		proof Proof
		now   time.Time
		want  error
	}{
		{"expired token", f.token, sign(ServiceRelay, f.token, "relay.netbird.io", f.now.Add(time.Hour)), f.now.Add(time.Hour), ErrTokenExpired},
		{"token signed by another key", foreign, sign(ServiceRelay, foreign, "relay.netbird.io", f.now), f.now, ErrBadTokenSig},
		{"tampered token", tampered, sign(ServiceRelay, tampered, "relay.netbird.io", f.now), f.now, ErrBadTokenSig},
		{"unknown key id", unknownKey, sign(ServiceRelay, unknownKey, "relay.netbird.io", f.now), f.now, ErrUnknownKeyID},
		{"truncated token", f.token[:10], sign(ServiceRelay, f.token[:10], "relay.netbird.io", f.now), f.now, ErrMalformedToken},
		{"stale proof", f.token, sign(ServiceRelay, f.token, "relay.netbird.io", f.now), f.now.Add(2 * DefaultSkew), ErrStaleProof},
		{"proof from the future", f.token, sign(ServiceRelay, f.token, "relay.netbird.io", f.now.Add(2*DefaultSkew)), f.now, ErrStaleProof},
		{"other verifier hostname", f.token, sign(ServiceRelay, f.token, "evil.example.com", f.now), f.now, ErrHostMismatch},
		{"proof for signal replayed to relay", f.token, sign(ServiceSignal, f.token, "relay.netbird.io", f.now), f.now, ErrBadProofSig},
		{"proof over another token", f.token, sign(ServiceRelay, foreign, "relay.netbird.io", f.now), f.now, ErrBadProofSig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.verifier.Verify(tc.token, tc.proof, tc.now)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestVerify_ProofHostnameIsSigned(t *testing.T) {
	f := newFixture(t, ServiceRelay)
	p, err := SignProof(f.authPriv, ServiceRelay, f.token, "evil.example.com", f.now)
	require.NoError(t, err)

	// A replayer rewrites the hostname to a name the verifier accepts: the signature no longer matches.
	p.Hostname = "relay.netbird.io"
	_, err = f.verifier.Verify(f.token, p, f.now)
	assert.ErrorIs(t, err, ErrBadProofSig)
}

func TestVerify_NoHostnameListStillBindsName(t *testing.T) {
	f := newFixture(t, ServiceRelay)
	f.verifier.Hostnames = nil
	p, err := SignProof(f.authPriv, ServiceRelay, f.token, "any.example.com", f.now)
	require.NoError(t, err)

	_, err = f.verifier.Verify(f.token, p, f.now)
	assert.NoError(t, err)
}

func TestUnmarshalRelayExtension_Malformed(t *testing.T) {
	for name, ext := range map[string][]byte{
		"short header":    {extTypeProof, 0x00},
		"length overflow": {extTypeProof, 0x00, 0x50, 0x01},
		"proof too short": {extTypeProof, 0x00, 0x01, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalRelayExtension(ext)
			assert.ErrorIs(t, err, ErrMalformedExtension, "garbled credentials must not look like a legacy client")
		})
	}
}

func TestUnmarshalRelayExtension_NoProof(t *testing.T) {
	for name, ext := range map[string][]byte{
		"empty":          nil,
		"no proof entry": {0x7f, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalRelayExtension(ext)
			assert.ErrorIs(t, err, ErrNoProof, "an extension without a proof is a legacy client")
		})
	}
}

func TestFromMetadata_MissingVsMalformed(t *testing.T) {
	_, _, err := FromMetadata(metadata.Pairs())
	assert.ErrorIs(t, err, ErrMissingCredentials, "no credentials is a legacy client")

	// A peer that presents anything must be validated, never treated as legacy.
	for name, md := range map[string]metadata.MD{
		"token only":   metadata.Pairs(MetadataToken, "x"),
		"no signature": metadata.Pairs(MetadataToken, "x", MetadataTimestamp, "1", MetadataHostname, "signal.netbird.io"),
		"bad timestamp": metadata.Pairs(MetadataToken, "x", MetadataTimestamp, "yesterday",
			MetadataHostname, "signal.netbird.io", MetadataSignature, "sig"),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := FromMetadata(md)
			assert.ErrorIs(t, err, ErrMalformedCredentials, "partial credentials must be refused")
		})
	}
}

func TestVerifyToken_RejectsUnsafeKeys(t *testing.T) {
	f := newFixtureWithAlgo(t, ServiceRelay, AlgoHMACSHA256)

	_, err := VerifyToken(f.token, TokenKeys{HMAC: map[KeyID][]byte{7: nil}}, f.now)
	assert.ErrorIs(t, err, ErrKeyConfig, "an empty HMAC secret makes tokens forgeable")
	_, err = VerifyToken(f.token, TokenKeys{HMAC: map[KeyID][]byte{7: []byte("short")}}, f.now)
	assert.ErrorIs(t, err, ErrKeyConfig, "a short HMAC secret must be refused")

	ed := newFixtureWithAlgo(t, ServiceRelay, AlgoEd25519)
	_, err = VerifyToken(ed.token, TokenKeys{Ed25519: map[KeyID]ed25519.PublicKey{7: make([]byte, 31)}}, ed.now)
	assert.ErrorIs(t, err, ErrKeyConfig, "a wrong-size Ed25519 key must be refused, not panic")
}

func TestVerify_HMACRoundTrip(t *testing.T) {
	f := newFixtureWithAlgo(t, ServiceRelay, AlgoHMACSHA256)
	p, err := SignProof(f.authPriv, ServiceRelay, f.token, "relay.netbird.io", f.now)
	require.NoError(t, err)

	tok, err := f.verifier.Verify(f.token, p, f.now)
	require.NoError(t, err)
	assert.Equal(t, AlgoHMACSHA256, tok.Algo, "token must report the algorithm it was issued with")
	assert.Equal(t, f.wg, tok.WGPub, "token must carry the WireGuard key it was issued for")
}

func TestVerifyToken_ModesAreMutuallyExclusive(t *testing.T) {
	ed := newFixtureWithAlgo(t, ServiceRelay, AlgoEd25519)
	hm := newFixtureWithAlgo(t, ServiceRelay, AlgoHMACSHA256)

	// The Ed25519 verifier also knows the secret an attacker may have stolen from any node.
	hmacToken, err := IssueHMACToken(hm.secret, Token{KeyID: 7, Expiry: ed.now.Add(time.Hour), WGPub: ed.wg, AuthPub: ed.authPriv.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	_, err = VerifyToken(hmacToken, ed.verifier.Keys, ed.now)
	assert.ErrorIs(t, err, ErrAlgoNotAccepted, "an Ed25519 verifier must reject HMAC tokens")

	_, err = VerifyToken(ed.token, hm.verifier.Keys, hm.now)
	assert.ErrorIs(t, err, ErrAlgoNotAccepted, "an HMAC verifier must reject Ed25519 tokens")

	both := TokenKeys{HMAC: hm.verifier.Keys.HMAC, Ed25519: ed.verifier.Keys.Ed25519}
	_, err = VerifyToken(ed.token, both, ed.now)
	assert.ErrorIs(t, err, ErrKeyConfig, "configuring both modes must be refused")

	_, err = VerifyToken(ed.token, TokenKeys{}, ed.now)
	assert.ErrorIs(t, err, ErrKeyConfig, "configuring no mode must be refused")
}

func TestVerifyToken_LegacyRelayTokenRejected(t *testing.T) {
	f := newFixtureWithAlgo(t, ServiceRelay, AlgoHMACSHA256)
	// Legacy Relay token: algo 1, HMAC over the decimal expiry.
	legacy := append([]byte{byte(AlgoHMACSHA256)}, make([]byte, 32)...)
	legacy = append(legacy, []byte("1800003600")...)

	_, err := VerifyToken(legacy, f.verifier.Keys, f.now)
	assert.ErrorIs(t, err, ErrMalformedToken)
}
