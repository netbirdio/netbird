package types

import (
	"github.com/netbirdio/netbird/management/server/integration_reference"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
)

const (
	GroupIssuedAPI         = "api"
	GroupIssuedJWT         = "jwt"
	GroupIssuedIntegration = "integration"
)

// Group of the peers for ACL
type Group struct {
	// ID of the group
	ID string `gorm:"primaryKey"`

	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`

	// Name visible in the UI
	Name string

	// Issued defines how this group was created (enum of "api", "integration" or "jwt")
	Issued string

	// Peers list of the group
	Peers      []string    `gorm:"-"` // Peers and GroupPeers list will be ignored when writing to the DB. Use AddPeerToGroup and RemovePeerFromGroup methods to modify group membership
	GroupPeers []GroupPeer `gorm:"foreignKey:GroupID;references:id;constraint:OnDelete:CASCADE;"`
	Users      []string    `gorm:"-"`
	GroupUsers []GroupUser `gorm:"foreignKey:GroupID;references:id;constraint:OnDelete:CASCADE;"`

	// Resources contains a list of resources in that group
	Resources []Resource `gorm:"serializer:json"`

	IntegrationReference integration_reference.IntegrationReference `gorm:"embedded;embeddedPrefix:integration_ref_"`
}

type GroupPeer struct {
	AccountID string `gorm:"index"`
	GroupID   string `gorm:"primaryKey"`
	PeerID    string `gorm:"primaryKey"`
}

type GroupUser struct {
	AccountID string `gorm:"index"`
	GroupID   string `gorm:"primaryKey"`
	UserID    string `gorm:"primaryKey"`
}

func (g *Group) LoadGroupPeers() {
	g.Peers = make([]string, len(g.GroupPeers))
	for i, peer := range g.GroupPeers {
		g.Peers[i] = peer.PeerID
	}
	g.GroupPeers = []GroupPeer{}
}

func (g *Group) StoreGroupPeers() {
	g.GroupPeers = make([]GroupPeer, len(g.Peers))
	for i, peer := range g.Peers {
		g.GroupPeers[i] = GroupPeer{
			AccountID: g.AccountID,
			GroupID:   g.ID,
			PeerID:    peer,
		}
	}
	g.Peers = []string{}
}

func (g *Group) LoadGroupUsers() {
	g.Users = make([]string, len(g.GroupUsers))
	for i, user := range g.GroupUsers {
		g.Users[i] = user.UserID
	}
	g.GroupUsers = []GroupUser{}
}

func (g *Group) StoreGroupUsers() {
	g.GroupUsers = make([]GroupUser, len(g.Users))
	for i, user := range g.Users {
		g.GroupUsers[i] = GroupUser{
			AccountID: g.AccountID,
			GroupID:   g.ID,
			UserID:    user,
		}
	}
	g.Users = []string{}
}

// EventMeta returns activity event meta related to the group
func (g *Group) EventMeta() map[string]any {
	return map[string]any{"name": g.Name}
}

func (g *Group) EventMetaResource(resource *types.NetworkResource) map[string]any {
	return map[string]any{"name": g.Name, "id": g.ID, "resource_name": resource.Name, "resource_id": resource.ID, "resource_type": resource.Type}
}

func (g *Group) Copy() *Group {
	group := &Group{
		ID:                   g.ID,
		AccountID:            g.AccountID,
		Name:                 g.Name,
		Issued:               g.Issued,
		Peers:                make([]string, len(g.Peers)),
		GroupPeers:           make([]GroupPeer, len(g.GroupPeers)),
		GroupUsers:           make([]GroupUser, len(g.GroupUsers)),
		Resources:            make([]Resource, len(g.Resources)),
		IntegrationReference: g.IntegrationReference,
	}
	copy(group.Peers, g.Peers)
	copy(group.GroupPeers, g.GroupPeers)
	copy(group.GroupUsers, g.GroupUsers)
	copy(group.Resources, g.Resources)
	return group
}

// HasPeers checks if the group has any peers.
func (g *Group) HasPeers() bool {
	return len(g.Peers) > 0
}

// IsGroupAll checks if the group is a default "All" group.
func (g *Group) IsGroupAll() bool {
	return g.Name == "All"
}

// AddPeer adds peerID to Peers if not present, returning true if added.
func (g *Group) AddPeer(peerID string) bool {
	if peerID == "" {
		return false
	}

	for _, itemID := range g.Peers {
		if itemID == peerID {
			return false
		}
	}

	g.Peers = append(g.Peers, peerID)
	return true
}

// RemovePeer removes peerID from Peers if present, returning true if removed.
func (g *Group) RemovePeer(peerID string) bool {
	for i, itemID := range g.Peers {
		if itemID == peerID {
			g.Peers = append(g.Peers[:i], g.Peers[i+1:]...)
			return true
		}
	}
	return false
}

// AddResource adds resource to Resources if not present, returning true if added.
func (g *Group) AddResource(resource Resource) bool {
	for _, item := range g.Resources {
		if item == resource {
			return false
		}
	}

	g.Resources = append(g.Resources, resource)
	return true
}

// RemoveResource removes resource from Resources if present, returning true if removed.
func (g *Group) RemoveResource(resource Resource) bool {
	for i, item := range g.Resources {
		if item == resource {
			g.Resources = append(g.Resources[:i], g.Resources[i+1:]...)
			return true
		}
	}
	return false
}

// HasResources checks if the group has any resources.
func (g *Group) HasResources() bool {
	return len(g.Resources) > 0
}
