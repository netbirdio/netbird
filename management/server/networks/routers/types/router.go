package types

import (
	"errors"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/networks/types"
)

type NetworkRouter struct {
	ID         string `gorm:"index"`
	NetworkID  string `gorm:"index"`
	AccountID  string `gorm:"index"`
	Peer       string
	PeerGroups []string `gorm:"serializer:json"`
	Masquerade bool
	Metric     int
	Enabled    bool
}

func NewNetworkRouter(accountID string, networkID string, peer string, peerGroups []string, masquerade bool, metric int, enabled bool) (*NetworkRouter, error) {
	if peer != "" && len(peerGroups) > 0 {
		return nil, errors.New("peer and peerGroups cannot be set at the same time")
	}

	return &NetworkRouter{
		ID:         xid.New().String(),
		AccountID:  accountID,
		NetworkID:  networkID,
		Peer:       peer,
		PeerGroups: peerGroups,
		Masquerade: masquerade,
		Metric:     metric,
		Enabled:    enabled,
	}, nil
}

func (n *NetworkRouter) ToAPIResponse() *api.NetworkRouter {
	return &api.NetworkRouter{
		Id:         n.ID,
		Peer:       &n.Peer,
		PeerGroups: &n.PeerGroups,
		Masquerade: n.Masquerade,
		Metric:     n.Metric,
		Enabled:    n.Enabled,
	}
}

func (n *NetworkRouter) FromAPIRequest(req *api.NetworkRouterRequest) {
	if req.Peer != nil {
		n.Peer = *req.Peer
	}

	if req.PeerGroups != nil {
		n.PeerGroups = *req.PeerGroups
	}

	n.Masquerade = req.Masquerade
	n.Metric = req.Metric
	n.Enabled = req.Enabled
}

func (n *NetworkRouter) Copy() *NetworkRouter {
	return &NetworkRouter{
		ID:         n.ID,
		NetworkID:  n.NetworkID,
		AccountID:  n.AccountID,
		Peer:       n.Peer,
		PeerGroups: n.PeerGroups,
		Masquerade: n.Masquerade,
		Metric:     n.Metric,
		Enabled:    n.Enabled,
	}
}

func (n *NetworkRouter) EventMeta(network *types.Network) map[string]any {
	return map[string]any{"network_name": network.Name, "network_id": network.ID, "peer": n.Peer, "peer_groups": n.PeerGroups}
}
