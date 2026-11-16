package exitnodes

import (
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ExitNode routes the default traffic of the peers in its distribution groups
// through its routing peers. Name becomes the route NetID clients select it by.
type ExitNode struct {
	ID                  string `gorm:"primaryKey"`
	AccountID           string `gorm:"index"`
	PublicID            string `gorm:"index"`
	Name                string
	Description         string
	Enabled             bool
	RoutingPeers        []RoutingPeer `gorm:"serializer:json"`
	Masquerade          bool
	Groups              []string `gorm:"serializer:json"`
	AccessControlGroups []string `gorm:"serializer:json"`
	AutoApply           bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// RoutingPeer is one routing entry of an exit node: a single peer or the peers
// of a set of groups, with its own metric. Exactly one of Peer and PeerGroups is set.
type RoutingPeer struct {
	ID         string   `json:"id"`
	PublicID   string   `json:"public_id"`
	Peer       string   `json:"peer,omitempty"`
	PeerGroups []string `json:"peer_groups,omitempty"`
	Metric     int      `json:"metric"`
	Enabled    bool     `json:"enabled"`
}

// TableName returns the table exit nodes are stored in.
func (ExitNode) TableName() string {
	return "exit_nodes"
}

// FromAPIRequest copies the fields of an API request onto the exit node. The
// routing peer IDs are taken as sent, so an update can match them to the
// stored entries; identifiers are assigned by the manager.
func (e *ExitNode) FromAPIRequest(req *api.ExitNodeRequest) {
	e.Name = req.Name
	e.Description = ""
	if req.Description != nil {
		e.Description = *req.Description
	}
	e.Enabled = req.Enabled
	e.Masquerade = req.Masquerade
	e.Groups = slices.Clone(req.Groups)
	e.AccessControlGroups = nil
	if req.AccessControlGroups != nil {
		e.AccessControlGroups = slices.Clone(*req.AccessControlGroups)
	}
	e.AutoApply = req.AutoApply

	e.RoutingPeers = make([]RoutingPeer, 0, len(req.RoutingPeers))
	for _, reqPeer := range req.RoutingPeers {
		e.RoutingPeers = append(e.RoutingPeers, routingPeerFromAPIRequest(reqPeer))
	}
}

func routingPeerFromAPIRequest(req api.ExitNodeRoutingPeerRequest) RoutingPeer {
	rp := RoutingPeer{
		Metric:  req.Metric,
		Enabled: req.Enabled,
	}
	if req.Id != nil {
		rp.ID = *req.Id
	}
	if req.Peer != nil {
		rp.Peer = *req.Peer
	}
	if req.PeerGroups != nil {
		rp.PeerGroups = slices.Clone(*req.PeerGroups)
	}
	return rp
}

// ToAPIResponse converts the exit node into its API representation. Public IDs
// are internal and never exposed.
func (e *ExitNode) ToAPIResponse() *api.ExitNode {
	routingPeers := make([]api.ExitNodeRoutingPeer, 0, len(e.RoutingPeers))
	for _, rp := range e.RoutingPeers {
		routingPeers = append(routingPeers, rp.toAPIResponse())
	}

	groups := slices.Clone(e.Groups)
	if groups == nil {
		groups = []string{}
	}
	accessControlGroups := slices.Clone(e.AccessControlGroups)
	if accessControlGroups == nil {
		accessControlGroups = []string{}
	}

	return &api.ExitNode{
		Id:                  e.ID,
		Name:                e.Name,
		Description:         e.Description,
		Enabled:             e.Enabled,
		RoutingPeers:        routingPeers,
		Masquerade:          e.Masquerade,
		Groups:              groups,
		AccessControlGroups: accessControlGroups,
		AutoApply:           e.AutoApply,
	}
}

func (rp RoutingPeer) toAPIResponse() api.ExitNodeRoutingPeer {
	resp := api.ExitNodeRoutingPeer{
		Id:      rp.ID,
		Metric:  rp.Metric,
		Enabled: rp.Enabled,
	}
	if rp.Peer != "" {
		peer := rp.Peer
		resp.Peer = &peer
	}
	if len(rp.PeerGroups) > 0 {
		peerGroups := slices.Clone(rp.PeerGroups)
		resp.PeerGroups = &peerGroups
	}
	return resp
}

// Copy returns a deep copy of the exit node.
func (e *ExitNode) Copy() *ExitNode {
	c := *e
	c.Groups = slices.Clone(e.Groups)
	c.AccessControlGroups = slices.Clone(e.AccessControlGroups)
	if e.RoutingPeers != nil {
		c.RoutingPeers = make([]RoutingPeer, 0, len(e.RoutingPeers))
		for _, rp := range e.RoutingPeers {
			c.RoutingPeers = append(c.RoutingPeers, rp.Copy())
		}
	}
	return &c
}

// Copy returns a deep copy of the routing peer.
func (rp RoutingPeer) Copy() RoutingPeer {
	rp.PeerGroups = slices.Clone(rp.PeerGroups)
	return rp
}

// EventMeta returns the activity event metadata of the exit node.
func (e *ExitNode) EventMeta() map[string]any {
	return map[string]any{"name": e.Name}
}

// Validate checks the exit node fields that need no lookup: the name, the
// shape of each routing peer entry and the presence of distribution groups.
func (e *ExitNode) Validate() error {
	if err := validateName(e.Name); err != nil {
		return err
	}

	if len(e.RoutingPeers) == 0 {
		return status.Errorf(status.InvalidArgument, "at least one routing peer is required")
	}
	for _, rp := range e.RoutingPeers {
		if err := rp.validate(); err != nil {
			return err
		}
	}

	if len(e.Groups) == 0 {
		return status.Errorf(status.InvalidArgument, "at least one distribution group is required")
	}
	if slices.Contains(e.Groups, "") || slices.Contains(e.AccessControlGroups, "") {
		return status.Errorf(status.InvalidArgument, "group ID should not be empty")
	}

	return nil
}

func validateName(name string) error {
	if n := utf8.RuneCountInString(name); n == 0 || n > route.MaxNetIDChar {
		return status.Errorf(status.InvalidArgument, "name should be between 1 and %d characters", route.MaxNetIDChar)
	}
	if strings.HasSuffix(name, route.V6ExitSuffix) {
		return status.Errorf(status.InvalidArgument, "name should not end with %q", route.V6ExitSuffix)
	}
	return nil
}

func (rp RoutingPeer) validate() error {
	if rp.Peer != "" && len(rp.PeerGroups) > 0 {
		return status.Errorf(status.InvalidArgument, "routing peer can not set both peer and peer_groups")
	}
	if rp.Peer == "" && len(rp.PeerGroups) == 0 {
		return status.Errorf(status.InvalidArgument, "routing peer requires either peer or peer_groups")
	}
	if slices.Contains(rp.PeerGroups, "") {
		return status.Errorf(status.InvalidArgument, "routing peer group ID should not be empty")
	}
	if rp.Metric < route.MinMetric || rp.Metric > route.MaxMetric {
		return status.Errorf(status.InvalidArgument, "routing peer metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}
	return nil
}
