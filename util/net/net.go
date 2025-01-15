package net

import (
	"net"

	"github.com/google/uuid"
)

const (
	// NetbirdFwmark is the fwmark value used by Netbird via wireguard
	NetbirdFwmark = 0x1BD00

	PreroutingFwmarkRedirected       = 0x1BD01
	PreroutingFwmarkMasquerade       = 0x1BD11
	PreroutingFwmarkMasqueradeReturn = 0x1BD12
)

// ConnectionID provides a globally unique identifier for network connections.
// It's used to track connections throughout their lifecycle so the close hook can correlate with the dial hook.
type ConnectionID string

type AddHookFunc func(connID ConnectionID, IP net.IP) error
type RemoveHookFunc func(connID ConnectionID) error

// GenerateConnID generates a unique identifier for each connection.
func GenerateConnID() ConnectionID {
	return ConnectionID(uuid.NewString())
}
