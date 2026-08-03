package types

import (
	"errors"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	sharedTypes "github.com/netbirdio/netbird/shared/management/types"
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

// ToComponent converts the router to its self-contained components
// representation. Returns nil for a nil router.
func (n *NetworkRouter) ToComponent() *sharedTypes.ComponentRouter {
	if n == nil {
		return nil
	}
	return &sharedTypes.ComponentRouter{
		NetworkID:  n.NetworkID,
		PublicID:   n.PublicID,
		Peer:       n.Peer,
		PeerGroups: n.PeerGroups,
		Masquerade: n.Masquerade,
		Metric:     n.Metric,
		Enabled:    n.Enabled,
	}
}

// ToComponentMap converts a peer-keyed router map to its components
// representation.
func ToComponentMap(routers map[string]*NetworkRouter) map[string]*sharedTypes.ComponentRouter {
	if routers == nil {
		return nil
	}
	out := make(map[string]*sharedTypes.ComponentRouter, len(routers))
	for id, r := range routers {
		out[id] = r.ToComponent()
	}
	return out
}

func NewNetworkRouter(accountID string, networkID string, peer string, peerGroups []string, masquerade bool, metric int, enabled bool) (*NetworkRouter, error) {
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

func (n *NetworkRouter) EventMeta(network *types.Network) map[string]any {
	return map[string]any{"network_name": network.Name, "network_id": network.ID, "peer": n.Peer, "peer_groups": n.PeerGroups}
}
