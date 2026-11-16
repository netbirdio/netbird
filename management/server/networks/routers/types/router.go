package types

import (
	"errors"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type NetworkRouter struct {
	ID         string `gorm:"primaryKey"`
	NetworkID  string `gorm:"index"`
	AccountID  string `gorm:"index"`
	PublicID   string `json:"-"`
	Peer       string
	PeerGroups []string `gorm:"serializer:json"`
	Masquerade bool
	Metric     int
	Enabled    bool
}

func NewNetworkRouter(accountID, networkID, peer string, peerGroups []string, masquerade bool, metric int, enabled bool) (*NetworkRouter, error) {
	r := &NetworkRouter{
		ID:         xid.New().String(),
		AccountID:  accountID,
		NetworkID:  networkID,
		Peer:       peer,
		PeerGroups: peerGroups,
		Masquerade: masquerade,
		Metric:     metric,
		Enabled:    enabled,
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	return r, nil
}

func (n *NetworkRouter) Validate() error {
	if n.Peer != "" && len(n.PeerGroups) > 0 {
		return errors.New("peer and peer_groups cannot be set at the same time")
	}

	if n.Peer == "" && len(n.PeerGroups) == 0 {
		return errors.New("either peer or peer_groups must be provided")
	}

	return nil
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
		PublicID:   n.PublicID,
		Peer:       n.Peer,
		PeerGroups: n.PeerGroups,
		Masquerade: n.Masquerade,
		Metric:     n.Metric,
		Enabled:    n.Enabled,
	}
}

func (n *NetworkRouter) Equal(other *NetworkRouter) bool {
	if n == nil || other == nil {
		return n == other
	}

	return n.ID == other.ID &&
		n.NetworkID == other.NetworkID &&
		n.AccountID == other.AccountID &&
		n.Peer == other.Peer &&
		n.Masquerade == other.Masquerade &&
		n.Metric == other.Metric &&
		n.Enabled == other.Enabled &&
		util.ElementsMatch(n.PeerGroups, other.PeerGroups)
}

func (n *NetworkRouter) EventMeta(network *types.Network) map[string]any {
	return map[string]any{"network_name": network.Name, "network_id": network.ID, "peer": n.Peer, "peer_groups": n.PeerGroups}
}
