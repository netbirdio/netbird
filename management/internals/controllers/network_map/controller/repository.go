package controller

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/server/agentnetwork"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Repository interface {
	GetAccountNetwork(ctx context.Context, accountID string) (*types.Network, error)
	GetAccountPeers(ctx context.Context, accountID string) ([]*peer.Peer, error)
	GetAccountByPeerID(ctx context.Context, peerID string) (*types.Account, error)
	GetPeersByIDs(ctx context.Context, accountID string, peerIDs []string) (map[string]*peer.Peer, error)
	GetPeerByID(ctx context.Context, accountID string, peerID string) (*peer.Peer, error)
	GetAccountZones(ctx context.Context, accountID string) ([]*zones.Zone, error)
	// SynthesizeAgentNetworkServices returns the in-memory reverse-proxy
	// services synthesised from the account's agent-network provider/policy
	// state. Empty for accounts without agent-network providers.
	SynthesizeAgentNetworkServices(ctx context.Context, accountID string) ([]*service.Service, error)
}

type repository struct {
	store store.Store
}

var _ Repository = (*repository)(nil)

func newRepository(s store.Store) Repository {
	return &repository{
		store: s,
	}
}

func (r *repository) GetAccountNetwork(ctx context.Context, accountID string) (*types.Network, error) {
	return r.store.GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
}

func (r *repository) GetAccountPeers(ctx context.Context, accountID string) ([]*peer.Peer, error) {
	return r.store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "")
}

func (r *repository) GetAccountByPeerID(ctx context.Context, peerID string) (*types.Account, error) {
	return r.store.GetAccountByPeerID(ctx, peerID)
}

func (r *repository) GetPeersByIDs(ctx context.Context, accountID string, peerIDs []string) (map[string]*peer.Peer, error) {
	return r.store.GetPeersByIDs(ctx, store.LockingStrengthNone, accountID, peerIDs)
}

func (r *repository) GetPeerByID(ctx context.Context, accountID string, peerID string) (*peer.Peer, error) {
	return r.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
}

func (r *repository) SynthesizeAgentNetworkServices(ctx context.Context, accountID string) ([]*service.Service, error) {
	return agentnetwork.SynthesizeServices(ctx, r.store, accountID)
}

func (r *repository) GetAccountZones(ctx context.Context, accountID string) ([]*zones.Zone, error) {
	return r.store.GetAccountZones(ctx, store.LockingStrengthNone, accountID)
}
