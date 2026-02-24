package network_map

//go:generate go run go.uber.org/mock/mockgen -package network_map -destination=interface_mock.go -source=./interface.go -build_flags=-mod=mod

import (
	"context"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	EnvNewNetworkMapBuilder  = "NB_EXPERIMENT_NETWORK_MAP"
	EnvNewNetworkMapAccounts = "NB_EXPERIMENT_NETWORK_MAP_ACCOUNTS"

	DnsForwarderPort           = nbdns.ForwarderServerPort
	OldForwarderPort           = nbdns.ForwarderClientPort
	DnsForwarderPortMinVersion = "v0.59.0"
)

type Controller interface {
	UpdateAccountPeers(ctx context.Context, accountID string) error
	UpdateAccountPeer(ctx context.Context, accountId string, peerId string) error
	BufferUpdateAccountPeers(ctx context.Context, accountID string) error
	GetValidatedPeerWithMap(ctx context.Context, isRequiresApproval bool, accountID string, p *nbpeer.Peer) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error)
	GetDNSDomain(settings *types.Settings) string
	StartWarmup(context.Context)
	GetNetworkMap(ctx context.Context, peerID string) (*types.NetworkMap, error)
	CountStreams() int

	OnPeersUpdated(ctx context.Context, accountId string, peerIDs []string) error
	OnPeersAdded(ctx context.Context, accountID string, peerIDs []string) error
	OnPeersDeleted(ctx context.Context, accountID string, peerIDs []string) error
	DisconnectPeers(ctx context.Context, accountId string, peerIDs []string)
	OnPeerConnected(ctx context.Context, accountID string, peerID string) (chan *UpdateMessage, error)
	OnPeerDisconnected(ctx context.Context, accountID string, peerID string)

	TrackEphemeralPeer(ctx context.Context, peer *nbpeer.Peer)
}
