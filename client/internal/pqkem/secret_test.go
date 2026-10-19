package pqkem

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pairWithSecrets builds a wired initiator ("bbbb") / responder ("aaaa") pair whose
// managers hold the given pre-shared secrets (nil = no secret).
func pairWithSecrets(t *testing.T, secretA, secretB []byte) (dA, dB *Manager, wgA, wgB *fakeWG) {
	t.Helper()
	sw := newSwitch()
	wgA, wgB = newFakeWG(), newFakeWG()
	dA = NewManager("aaaa", wgA, nil, WithPresharedSecret(secretA))
	dB = NewManager("bbbb", wgB, nil, WithPresharedSecret(secretB))
	dA.Start(&loopback{ep: epA, sw: sw})
	dB.Start(&loopback{ep: epB, sw: sw})
	dA.AddPeer("bbbb", epB)
	dB.AddPeer("aaaa", epA)
	t.Cleanup(func() {
		dA.Stop()
		dB.Stop()
	})
	return dA, dB, wgA, wgB
}

// TestManager_PresharedSecretBindsPSK covers the configured-secret contract (a host
// option like WireGuard's --pre-shared-key: only peers holding the same secret may
// communicate). Without binding the secret into the derivation, two peers with
// different secrets derived the same PSK and the secret was silently bypassed. The PSK
// must match only when the secrets match, for the bootstrap and for a rotation alike.
func TestManager_PresharedSecretBindsPSK(t *testing.T) {
	secret1 := []byte("configured-secret-one-0123456789")
	secret2 := []byte("configured-secret-two-0123456789")
	cases := map[string]struct {
		a, b  []byte
		match bool
	}{
		"same secret":                {a: secret1, b: secret1, match: true},
		"different secrets":          {a: secret1, b: secret2, match: false},
		"only the responder has one": {a: secret1, b: nil, match: false},
		"only the initiator has one": {a: nil, b: secret1, match: false},
		"no secret":                  {a: nil, b: nil, match: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dA, dB, wgA, wgB := pairWithSecrets(t, tc.a, tc.b)

			bootstrap(t, dA, dB)
			bootA, bootB := wgA.psk("bbbb"), wgB.psk("aaaa")
			require.NotEqual(t, PSK{}, bootA, "responder must derive a bootstrap PSK")
			require.NotEqual(t, PSK{}, bootB, "initiator must derive a bootstrap PSK")
			assert.Equal(t, tc.match, bootA == bootB, "bootstrap PSKs must match only when the secrets match")

			// Rotation over the data path re-derives the PSK; it must honour the secret too.
			dB.OnDataPathRekeyed("aaaa", 0)
			require.Eventually(t, func() bool {
				return wgA.psk("bbbb") != bootA && wgB.psk("aaaa") != bootB
			}, time.Second, 5*time.Millisecond, "the rotation must re-key both peers")
			assert.Equal(t, tc.match, wgA.psk("bbbb") == wgB.psk("aaaa"), "rotated PSKs must match only when the secrets match")
		})
	}
}
