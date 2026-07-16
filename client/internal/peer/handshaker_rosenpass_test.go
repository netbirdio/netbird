package peer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeRPResolver struct {
	localHash []byte
	ack       []byte
	hasLocal  bool
}

func (f fakeRPResolver) LocalPubKeyHash() []byte              { return f.localHash }
func (f fakeRPResolver) RemotePubKeyAck(string) []byte        { return f.ack }
func (f fakeRPResolver) RemoteHasLocalKey(remote string) bool { return f.hasLocal }

func TestSetRosenpassPubKey_NoResolverAlwaysSendsFullKey(t *testing.T) {
	localKey := []byte{1, 2, 3}
	h := &Handshaker{config: ConnConfig{RosenpassConfig: RosenpassConfig{PubKey: localKey}}}

	var a OfferAnswer
	h.setRosenpassPubKey(&a)

	require.Equal(t, localKey, a.RosenpassPubKey)
	require.Nil(t, a.RosenpassPubKeyHash)
	require.Nil(t, a.RosenpassPubKeyAck)
}

func TestSetRosenpassPubKey_ResolverIncludesFullKeyUntilAcked(t *testing.T) {
	localKey := []byte{1, 2, 3}
	res := fakeRPResolver{localHash: []byte{9}, ack: []byte{8}, hasLocal: false}
	h := &Handshaker{config: ConnConfig{Key: "peerA", RosenpassConfig: RosenpassConfig{PubKey: localKey, KeyResolver: res}}}

	var a OfferAnswer
	h.setRosenpassPubKey(&a)

	require.Equal(t, localKey, a.RosenpassPubKey, "full key must be sent until the peer acks it")
	require.Equal(t, []byte{9}, a.RosenpassPubKeyHash)
	require.Equal(t, []byte{8}, a.RosenpassPubKeyAck)
}

func TestSetRosenpassPubKey_ResolverOmitsFullKeyOnceAcked(t *testing.T) {
	localKey := []byte{1, 2, 3}
	res := fakeRPResolver{localHash: []byte{9}, ack: []byte{8}, hasLocal: true}
	h := &Handshaker{config: ConnConfig{Key: "peerA", RosenpassConfig: RosenpassConfig{PubKey: localKey, KeyResolver: res}}}

	var a OfferAnswer
	h.setRosenpassPubKey(&a)

	require.Nil(t, a.RosenpassPubKey, "full key must be omitted once the peer holds it")
	require.Equal(t, []byte{9}, a.RosenpassPubKeyHash)
	require.Equal(t, []byte{8}, a.RosenpassPubKeyAck)
}

func TestSetRosenpassPubKey_DisabledSetsNothing(t *testing.T) {
	h := &Handshaker{config: ConnConfig{RosenpassConfig: RosenpassConfig{}}}

	var a OfferAnswer
	h.setRosenpassPubKey(&a)

	require.Nil(t, a.RosenpassPubKey)
	require.Nil(t, a.RosenpassPubKeyHash)
}
