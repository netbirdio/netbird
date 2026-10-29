package peerliveness

//go:generate go tool mockgen -package peerliveness -destination=interface_mock.go -source=./interface.go -build_flags=-mod=mod

import (
	"context"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

// Controller owns the liveness of this management instance and of the peers it serves.
// It heartbeats the instance row, sweeps the peers of dead instances and records which
// peer connections this instance holds.
type Controller interface {
	// Start registers the instance under a fresh ID, sweeps dead instances once
	// synchronously and then runs the heartbeat loop until ctx is done or Release is called.
	Start(ctx context.Context) error
	// Connect claims the peer's connection for this instance when session is newer than the
	// stored one. It returns false when a newer session already owns the peer and an error
	// before Start. The write goes through st, which may be bound to the caller's transaction.
	Connect(ctx context.Context, st Store, accountID, peerID string, session int64) (bool, error)
	// Disconnect releases the peer's connection when it still carries session. It returns
	// false when a newer session owns the peer or no connection exists. The write goes
	// through st, which may be bound to the caller's transaction.
	Disconnect(ctx context.Context, st Store, peerID string, session int64) (bool, error)
	// ReleaseConnection releases the peer's connection whatever its session, so no stream of
	// this instance can resurrect it. The write goes through st, which may be bound to the
	// caller's transaction.
	ReleaseConnection(ctx context.Context, st Store, peerID string) error
	// ForgetPeer drops the registry entry of a peer once it and its connection record are
	// deleted, so it is not re-registered after a heartbeat lapse.
	ForgetPeer(peerID string)
	// ForgetAccount drops the registry entries of the account's peers once the account and
	// its connection records are deleted, so they are not re-registered after a heartbeat lapse.
	ForgetAccount(accountID string)
	// Release stops the heartbeat loop and retires the instance on clean shutdown.
	Release(ctx context.Context) error
	// InstanceID returns the current instance ID, empty before Start.
	InstanceID() string
}

// Store is the part of the store the liveness controller depends on.
type Store interface {
	RegisterInstance(ctx context.Context, id, hostname string) error
	HeartbeatInstance(ctx context.Context, id string) (bool, error)
	ListStaleInstances(ctx context.Context) ([]nbpeer.ManagementInstance, error)
	SweepInstanceChunk(ctx context.Context, instanceID string, lastSeen time.Time, limit int) (int, error)
	DeleteInstanceIfStale(ctx context.Context, id string) (bool, error)
	ReleaseInstance(ctx context.Context, id string) error
	ConnectPeer(ctx context.Context, accountID, peerID, instanceID string, session int64) (bool, error)
	DisconnectPeer(ctx context.Context, peerID string, session int64) (bool, error)
	ReleasePeerConnection(ctx context.Context, peerID string) error
	ReRegisterPeers(ctx context.Context, instanceID string, sessions []types.PeerSession) error
}
