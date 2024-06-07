package net

import (
	"github.com/netbirdio/netbird/iface/netstack"
	"os"

	"github.com/google/uuid"
)

const (
	// NetbirdFwmark is the fwmark value used by Netbird via wireguard
	NetbirdFwmark = 0x1BD00

	envDisableCustomRouting = "NB_DISABLE_CUSTOM_ROUTING"
)

// ConnectionID provides a globally unique identifier for network connections.
// It's used to track connections throughout their lifecycle so the close hook can correlate with the dial hook.
type ConnectionID string

// GenerateConnID generates a unique identifier for each connection.
func GenerateConnID() ConnectionID {
	return ConnectionID(uuid.NewString())
}

func CustomRoutingDisabled() bool {
	if netstack.IsEnabled() {
		return true
	}
	return os.Getenv(envDisableCustomRouting) == "true"
}
