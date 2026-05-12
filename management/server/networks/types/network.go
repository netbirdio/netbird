package types

import (
	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

type Network struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index"`

	// AccountSeqID is a per-account monotonically increasing identifier used as the
	// compact wire id when sending NetworkMap components to capable peers.
	AccountSeqID uint32 `json:"-" gorm:"index:idx_networks_account_seq_id;not null;default:0"`

	Name        string
	Description string
}

// HasSeqID reports whether the network has been persisted long enough to have
// a per-account sequence id allocated. Wire encoders that key off AccountSeqID
// must skip networks that return false here.
func (n *Network) HasSeqID() bool {
	return n != nil && n.AccountSeqID != 0
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

// Copy returns a copy of a network.
func (n *Network) Copy() *Network {
	return &Network{
		ID:           n.ID,
		AccountID:    n.AccountID,
		AccountSeqID: n.AccountSeqID,
		Name:         n.Name,
		Description:  n.Description,
	}
}

func (n *Network) EventMeta() map[string]any {
	return map[string]any{"name": n.Name}
}
