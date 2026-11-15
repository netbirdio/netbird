package server

import (
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/server/store"
)

type mocEbpfMgr struct {
}

func (m mocEbpfMgr) AddPeer(channelID, dstID uint16, dstAddr netip.AddrPort) error {
	return nil
}

type mocPeer struct {
	id   messages.PeerID
	addr netip.AddrPort
}

func (m mocPeer) Close() {

}

func (m mocPeer) ID() messages.PeerID {
	return m.id
}

func (m mocPeer) RemoteAddress() netip.AddrPort {
	return m.addr
}

func (m mocPeer) Write(b []byte) (int, error) {
	return len(b), nil
}

func TestNewChannelManager(t *testing.T) {
	peerA := &mocPeer{
		id:   messages.HashID("peer_a"),
		addr: netip.MustParseAddrPort("10.0.0.1:1234"),
	}
	peerB := &mocPeer{
		id:   messages.HashID("peer_b"),
		addr: netip.MustParseAddrPort("10.0.0.2:1234"),
	}

	peerStore := store.NewStore()
	peerStore.AddPeer(peerA)
	peerStore.AddPeer(peerB)

	cm := NewChannelManager(peerStore, &mocEbpfMgr{})
	cm.Add(peerA.ID(), peerB.ID())
	cm.Add(peerB.ID(), peerA.ID())
}
