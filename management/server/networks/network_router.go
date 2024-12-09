package networks

import (
	"errors"

	"github.com/rs/xid"
)

type NetworkRouter struct {
	ID         string `gorm:"index"`
	NetworkID  string `gorm:"index"`
	Peer       string
	PeerGroups []string `gorm:"serializer:json"`
	Masquerade bool
	Metric     int
}

func NewNetworkRouter(networkID string, peer string, peerGroups []string, masquerade bool, metric int) (*NetworkRouter, error) {
	if peer != "" && len(peerGroups) > 0 {
		return nil, errors.New("peer and peerGroups cannot be set at the same time")
	}

	return &NetworkRouter{
		ID:         xid.New().String(),
		NetworkID:  networkID,
		Peer:       peer,
		PeerGroups: peerGroups,
		Masquerade: masquerade,
		Metric:     metric,
	}, nil
}
