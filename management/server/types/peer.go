package types

import (
	"net"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// MapReuse names the network serial a reconnecting peer is known to hold. Sync skips
// computing the peer's map when nothing about the peer changed and the account's
// network serial still equals it.
type MapReuse struct {
	// Serial is the account network serial last delivered to the peer.
	Serial uint64
}

// PeerSyncResult is the outcome of syncing a peer that opened a Sync stream.
type PeerSyncResult struct {
	Peer *nbpeer.Peer
	// NetworkMap is nil when MapReused is true.
	NetworkMap       *NetworkMap
	PostureChecks    []*nmdata.PostureChecks
	DNSForwarderPort int64
	// PeerNotValid reports that the peer failed integrated validation, so its map
	// is empty.
	PeerNotValid bool
	// MapReused reports that the peer still holds the map of the account's current
	// network serial, so the map was not computed.
	MapReused bool
}

// PeerSync used as a data object between the gRPC API and Manager on Sync request.
type PeerSync struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
	// Meta is the system information passed by peer, must be always present
	Meta nbpeer.PeerSystemMeta
	// RealIP is the peer's connection IP, used to refresh its geo location.
	// May be nil when the request has no associated connection IP.
	RealIP net.IP
	// UpdateAccountPeers indicate updating account peers,
	// which occurs when the peer's metadata is updated
	UpdateAccountPeers bool
}

// PeerLogin used as a data object between the gRPC API and Manager on Login request.
type PeerLogin struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
	// SSHKey is a peer's ssh key. Can be empty (e.g., old version do not provide it, or this feature is disabled)
	SSHKey string
	// Meta is the system information passed by peer, must be always present.
	Meta nbpeer.PeerSystemMeta
	// UserID indicates that JWT was used to log in, and it was valid. Can be empty when SetupKey is used or auth is not required.
	UserID string
	// SetupKey references to a server.SetupKey to log in. Can be empty when UserID is used or auth is not required.
	SetupKey string
	// ConnectionIP is the real IP of the peer
	ConnectionIP net.IP

	// ExtraDNSLabels is a list of extra DNS labels that the peer wants to use
	ExtraDNSLabels []string
}
