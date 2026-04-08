//go:build android

package android

import "github.com/netbirdio/netbird/client/internal/peer"

// Connection status constants exported via gomobile.
const (
	ConnStatusIdle       = int(peer.StatusIdle)
	ConnStatusConnecting = int(peer.StatusConnecting)
	ConnStatusConnected  = int(peer.StatusConnected)
)

// PeerInfo describe information about the peers. It designed for the UI usage
type PeerInfo struct {
	IP         string
	FQDN       string
	ConnStatus int
	Routes     PeerRoutes
}

func (p *PeerInfo) GetPeerRoutes() *PeerRoutes {
	return &p.Routes
}

// PeerInfoArray is a wrapper of []PeerInfo
type PeerInfoArray struct {
	items []PeerInfo
}

// Add new PeerInfo to the collection
func (array *PeerInfoArray) Add(s PeerInfo) *PeerInfoArray {
	array.items = append(array.items, s)
	return array
}

// Get return an element of the collection
func (array *PeerInfoArray) Get(i int) *PeerInfo {
	return &array.items[i]
}

// Size return with the size of the collection
func (array *PeerInfoArray) Size() int {
	return len(array.items)
}
