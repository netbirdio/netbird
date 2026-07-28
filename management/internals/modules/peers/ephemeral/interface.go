package ephemeral

import (
	"context"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	EphemeralLifeTime = 10 * time.Minute
)

type Manager interface {
	LoadInitialPeers(ctx context.Context)
	Stop()
	OnPeerConnected(ctx context.Context, peer *nbpeer.Peer)
	OnPeerDisconnected(ctx context.Context, peer *nbpeer.Peer)
}
