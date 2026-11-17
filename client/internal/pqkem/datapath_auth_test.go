package pqkem

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealForPeer seals a data-path frame under the PSK m currently shares with remoteID, as
// a genuine sender would.
func sealForPeer(t *testing.T, m *Manager, remoteID RemoteID, frame []byte) []byte {
	t.Helper()
	psk, ok := m.PSK(remoteID)
	require.True(t, ok, "sealing needs an established PSK")
	key, err := dataPathMACKey(psk)
	require.NoError(t, err)
	return sealDataPath(key, frame)
}

func TestDataPathSealOpen(t *testing.T) {
	key, err := dataPathMACKey(PSK{1})
	require.NoError(t, err)
	otherKey, err := dataPathMACKey(PSK{2})
	require.NoError(t, err)
	frame := []byte("kem frame")

	sealed := sealDataPath(key, frame)
	got, ok := openDataPath(key, sealed)
	require.True(t, ok, "a frame sealed under the key must open")
	assert.Equal(t, frame, got, "opening must return the original frame")

	_, ok = openDataPath(otherKey, sealed)
	assert.False(t, ok, "a different key must not open the frame")

	tampered := append([]byte(nil), sealed...)
	tampered[0] ^= 0x01
	_, ok = openDataPath(key, tampered)
	assert.False(t, ok, "a modified frame must not open")

	_, ok = openDataPath(key, sealed[:dataPathTagSize-1])
	assert.False(t, ok, "a datagram shorter than a tag must not open")
}

// TestManager_DataPathRejectsAuthenticatedBootstrap verifies a bootstrap is never taken
// from the data path, even with a valid MAC: the data path only carries rotations of an
// exchange that signalling already established.
func TestManager_DataPathRejectsAuthenticatedBootstrap(t *testing.T) {
	dA, dB, wgA, _, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	psk := wgA.psk("bbbb")

	require.NoError(t, dA.OnDataPathMessage("bbbb", sealForPeer(t, dA, "bbbb", forgedOffer(t, ExchangeID{}))))

	assert.Equal(t, psk, wgA.psk("bbbb"), "a bootstrap offer over the data path must be dropped")
}

// TestManager_DataPathRetransmitAfterCommitIsAnswered covers a lost answer. The responder
// commits the rotated PSK when it answers, so the initiator's retransmission, still sealed
// under the previous PSK, must be accepted under that key and answered, or the two peers
// never converge.
func TestManager_DataPathRetransmitAfterCommitIsAnswered(t *testing.T) {
	sw := newSwitch()
	wgA, wgB := newFakeWG(), newFakeWG()
	dA := NewManager("aaaa", wgA, nil) // responder
	dB := NewManager("bbbb", wgB, nil) // initiator
	dB.retryInterval = 20 * time.Millisecond
	lbA := &loopback{ep: epA, sw: sw}
	dA.Start(lbA)
	dB.Start(&loopback{ep: epB, sw: sw})
	dA.AddPeer("bbbb", epB)
	dB.AddPeer("aaaa", epA)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	boot := wgB.psk("aaaa")

	lbA.drop.Store(true) // lose the responder's answers
	dB.OnDataPathRekeyed("aaaa", 0)
	require.Eventually(t, func() bool { return wgA.psk("bbbb") != boot }, time.Second, 5*time.Millisecond,
		"the responder must commit the rotated PSK")
	lbA.drop.Store(false)

	require.Eventually(t, func() bool { return wgB.psk("aaaa") == wgA.psk("bbbb") }, 2*time.Second, 5*time.Millisecond,
		"the retransmitted offer must be answered so both peers converge")
}

// forgedOffer builds a well-formed KEM offer that no peer authenticated: fresh KEM
// material, the given AckID, and no data-path MAC.
func forgedOffer(t *testing.T, ack ExchangeID) []byte {
	t.Helper()
	ini, err := NewInitiator()
	require.NoError(t, err)
	id, err := newExchangeID()
	require.NoError(t, err)
	raw, err := (&OfferMsg{ExchangeID: id, AckID: ack, KEMOffer: ini.Offer()}).Encode()
	require.NoError(t, err)
	return raw
}

// TestManager_DataPathRejectsForgedOffer covers spoofed data-path datagrams. The data-path
// socket only knows the sender by source IP:port, and on a host-bound socket a datagram
// with a spoofed source can arrive from a physical interface rather than the tunnel. An
// unauthenticated offer must not re-key the responder: a forged bootstrap (zero AckID)
// used to be adopted, desynchronising the peers' PSKs. A guessed AckID is covered too.
func TestManager_DataPathRejectsForgedOffer(t *testing.T) {
	guessed, err := newExchangeID()
	require.NoError(t, err)
	cases := map[string]ExchangeID{
		"forged bootstrap (zero AckID)":   {},
		"forged rotation (guessed AckID)": guessed,
	}
	for name, ack := range cases {
		t.Run(name, func(t *testing.T) {
			dA, dB, wgA, _, _ := pair(t) // dB ("bbbb") initiator, dA ("aaaa") responder
			defer dA.Stop()
			defer dB.Stop()

			bootstrap(t, dA, dB)
			psk := wgA.psk("bbbb")
			require.NotEqual(t, PSK{}, psk, "bootstrap must establish a PSK")

			// Spoofed: it arrives from the initiator's registered data-path endpoint.
			dA.onDataPathInbound(epB, forgedOffer(t, ack))

			assert.Equal(t, psk, wgA.psk("bbbb"), "a forged data-path offer must not re-key the responder")
			current, ok := dA.PSK("bbbb")
			require.True(t, ok)
			assert.Equal(t, psk, current, "the responder's stored PSK must be unchanged")
		})
	}
}
