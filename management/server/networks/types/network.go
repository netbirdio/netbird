package types

import (
	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/http/api"
)

type Network struct {
	ID          string `gorm:"index"`
	AccountID   string `gorm:"index"`
	Name        string
	Description string
}

func NewNetwork(accountId, name, description string) *Network {
	return &Network{
		ID:          xid.New().String(),
		AccountID:   accountId,
		Name:        name,
		Description: description,
	}
}

func (n *Network) ToAPIResponse(routerIDs []string, resourceIDs []string, routingPeersCount int, policyIDs []string) *api.Network {
	return &api.Network{
		Id:                n.ID,
		Name:              n.Name,
		Description:       &n.Description,
		Routers:           routerIDs,
		Resources:         resourceIDs,
		RoutingPeersCount: routingPeersCount,
		Policies:          policyIDs,
	}
}

func (n *Network) FromAPIRequest(req *api.NetworkRequest) {
	n.Name = req.Name
	if req.Description != nil {
		n.Description = *req.Description
	}
}

// Copy returns a copy of a posture checks.
func (n *Network) Copy() *Network {
	return &Network{
		ID:          n.ID,
		AccountID:   n.AccountID,
		Name:        n.Name,
		Description: n.Description,
	}
}

func (n *Network) EventMeta() map[string]any {
	return map[string]any{"name": n.Name}
}
