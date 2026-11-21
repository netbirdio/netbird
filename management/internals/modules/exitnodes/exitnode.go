package exitnodes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	// PolicyResourceType is the policy rule destination resource type that targets an exit node.
	PolicyResourceType = "exit_node"

	// MaxNameLength matches the route network identifier limit.
	MaxNameLength = 40
	// MinMetric is the lowest allowed peer metric.
	MinMetric = 1
	// MaxMetric is the highest allowed peer metric.
	MaxMetric = 9999
)

// ID identifies an exit node.
type ID string

// Peer is a peer that routes internet traffic for an exit node.
type Peer struct {
	ExitNodeID ID     `gorm:"primaryKey"`
	PeerID     string `gorm:"primaryKey;uniqueIndex:idx_exit_node_peers_account_peer,priority:2"`
	// PublicID identifies the peer's router in the network map sent to clients.
	PublicID string
	// AccountID backs the unique index that keeps a peer in at most one exit node.
	AccountID string `gorm:"uniqueIndex:idx_exit_node_peers_account_peer,priority:1"`
	Metric    int
	Enabled   bool
}

// TableName keeps exit node peers out of the peers table.
func (Peer) TableName() string {
	return "exit_node_peers"
}

// ExitNode is a named set of peers that route internet traffic for the peers its policies allow.
type ExitNode struct {
	ID        ID     `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	// PublicID identifies the exit node in the network map sent to clients.
	PublicID    string `gorm:"index"`
	Name        string
	Description string
	Enabled     bool
	AutoApply   bool
	Peers       []Peer `gorm:"foreignKey:ExitNodeID;references:ID"`
}

// TableName returns the exit nodes table name.
func (ExitNode) TableName() string {
	return "exit_nodes"
}

// BindPeers sets the exit node and account of every peer to those of the exit node.
func (e *ExitNode) BindPeers() {
	for i := range e.Peers {
		e.Peers[i].ExitNodeID = e.ID
		e.Peers[i].AccountID = e.AccountID
	}
}

// FromAPIRequest fills the exit node from an API request, trimming the name.
func (e *ExitNode) FromAPIRequest(req *api.ExitNodeRequest) {
	e.Name = strings.TrimSpace(req.Name)
	e.Description = ""
	if req.Description != nil {
		e.Description = *req.Description
	}
	e.Enabled = req.Enabled
	e.AutoApply = req.AutoApply

	e.Peers = make([]Peer, 0, len(req.Peers))
	for _, p := range req.Peers {
		e.Peers = append(e.Peers, Peer{PeerID: p.PeerId, Metric: p.Metric, Enabled: p.Enabled})
	}
}

// ToAPIResponse converts the exit node to its API representation.
func (e *ExitNode) ToAPIResponse() *api.ExitNode {
	peers := make([]api.ExitNodePeer, 0, len(e.Peers))
	for _, p := range e.Peers {
		peers = append(peers, api.ExitNodePeer{PeerId: p.PeerID, Metric: p.Metric, Enabled: p.Enabled})
	}

	description := e.Description
	return &api.ExitNode{
		Id:          string(e.ID),
		Name:        e.Name,
		Description: &description,
		Enabled:     e.Enabled,
		AutoApply:   e.AutoApply,
		Peers:       peers,
	}
}

// Validate checks the rules that do not depend on other exit nodes or on the account.
func (e *ExitNode) Validate() error {
	if e.Name == "" {
		return errors.New("exit node name is required")
	}
	if len(e.Name) > MaxNameLength {
		return fmt.Errorf("exit node name must be at most %d characters", MaxNameLength)
	}
	if len(e.Peers) == 0 {
		return errors.New("exit node must have at least one peer")
	}

	seen := make(map[string]struct{}, len(e.Peers))
	for _, p := range e.Peers {
		if p.PeerID == "" {
			return errors.New("peer ID is required")
		}
		if p.Metric < MinMetric || p.Metric > MaxMetric {
			return fmt.Errorf("metric of peer %s must be between %d and %d", p.PeerID, MinMetric, MaxMetric)
		}
		if _, ok := seen[p.PeerID]; ok {
			return fmt.Errorf("peer %s appears more than once", p.PeerID)
		}
		seen[p.PeerID] = struct{}{}
	}

	return nil
}

// PeerIDs returns the IDs of all peers of the exit node.
func (e *ExitNode) PeerIDs() []string {
	ids := make([]string, 0, len(e.Peers))
	for _, p := range e.Peers {
		ids = append(ids, p.PeerID)
	}
	return ids
}

// Copy returns a deep copy of the exit node.
func (e *ExitNode) Copy() *ExitNode {
	c := *e
	c.Peers = append([]Peer(nil), e.Peers...)
	return &c
}

// NewNotFoundError returns the error for an exit node that does not exist in the account.
func NewNotFoundError(exitNodeID ID) error {
	return status.Errorf(status.NotFound, "exit node %s not found", exitNodeID)
}
