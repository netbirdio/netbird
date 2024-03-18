package types

import "net/netip"

const (
	// InvalidNetwork invalid network type
	InvalidNetwork NetworkType = iota
	// IPv4Network IPv4 network type
	IPv4Network
	// IPv6Network IPv6 network type
	IPv6Network
)

// NetworkType route network type
type NetworkType int

type Route interface {
	GetID() string
	IsEnabled() bool
	GetPeer() string
	SetPeer(string)
}

type DefaultRoute struct {
	ID string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID   string       `gorm:"index"`
	Network     netip.Prefix `gorm:"serializer:gob"`
	NetID       string
	Description string
	Peer        string
	PeerGroups  []string `gorm:"serializer:gob"`
	NetworkType NetworkType
	Masquerade  bool
	Metric      int
	Enabled     bool
	Groups      []string `gorm:"serializer:json"`
}

func (r *DefaultRoute) GetID() string {
	return r.ID
}

func (r *DefaultRoute) IsEnabled() bool {
	return r.Enabled
}

func (r *DefaultRoute) GetPeer() string {
	return r.Peer
}

func (r *DefaultRoute) SetPeer(peer string) {
	r.Peer = peer
}
