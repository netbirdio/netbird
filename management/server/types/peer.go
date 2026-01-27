package types

import (
	"net"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// PeerSync used as a data object between the gRPC API and Manager on Sync request.
type PeerSync struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
	// Meta is the system information passed by peer, must be always present
	Meta nbpeer.PeerSystemMeta
	// UpdateAccountPeers indicate updating account peers,
	// which occurs when the peer's metadata is updated
	UpdateAccountPeers bool
	// NetworkMapSerial is the last known network map serial number on the client.
	// Used to skip network map recalculation if client already has the latest.
	NetworkMapSerial uint64
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
