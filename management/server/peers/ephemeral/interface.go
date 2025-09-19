package ephemeral

import (
	"context"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type Manager interface {
	LoadInitialPeers(ctx context.Context)
	Stop()
	OnPeerConnected(ctx context.Context, peer *nbpeer.Peer)
	OnPeerDisconnected(ctx context.Context, peer *nbpeer.Peer)
}
