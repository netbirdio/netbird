package rosenpass

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func newCacheTestManager(spk []byte) *Manager {
	return &Manager{
		spk:               spk,
		remotePubKeys:     make(map[string][]byte),
		remoteHasLocalKey: make(map[string]bool),
	}
}

func TestResolveRemotePubKey(t *testing.T) {
	m := newCacheTestManager([]byte{0x01, 0x02})
	full := bytes.Repeat([]byte{0xAB}, 64)

	// a received full key is cached and returned
	require.Equal(t, full, m.ResolveRemotePubKey("peerA", full, nil))

	// a later hash-only message resolves from the cache
	require.Equal(t, full, m.ResolveRemotePubKey("peerA", nil, rawRosenpassKeyHash(full)))

	// hash mismatch is a cache miss
	require.Nil(t, m.ResolveRemotePubKey("peerA", nil, bytes.Repeat([]byte{0x01}, 32)))

	// no key and no hash (remote without Rosenpass) resolves to nil
	require.Nil(t, m.ResolveRemotePubKey("peerB", nil, nil))
}

func TestRemotePubKeyAck(t *testing.T) {
	m := newCacheTestManager([]byte{0x01})

	// unknown peer -> no ack (signals "send me the full key")
	require.Nil(t, m.RemotePubKeyAck("peerA"))

	full := bytes.Repeat([]byte{0x09}, 48)
	m.ResolveRemotePubKey("peerA", full, nil)
	require.Equal(t, rawRosenpassKeyHash(full), m.RemotePubKeyAck("peerA"))
}

func TestSetRemoteAckAndRemoteHasLocalKey(t *testing.T) {
	m := newCacheTestManager(bytes.Repeat([]byte{0x07}, 100))

	require.False(t, m.RemoteHasLocalKey("peerA"))

	// an ack matching our own key hash marks the peer as holding our key
	m.SetRemoteAck("peerA", m.LocalPubKeyHash())
	require.True(t, m.RemoteHasLocalKey("peerA"))

	// empty ack clears it
	m.SetRemoteAck("peerA", nil)
	require.False(t, m.RemoteHasLocalKey("peerA"))

	// a non-matching ack does not count
	m.SetRemoteAck("peerA", bytes.Repeat([]byte{0x01}, 32))
	require.False(t, m.RemoteHasLocalKey("peerA"))
}
