package net

import (
	"math/big"
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

func GetLastIPFromNetwork(network *net.IPNet, fromEnd int) net.IP {
	// Calculate the last IP in the CIDR range
	var endIP net.IP
	for i := 0; i < len(network.IP); i++ {
		endIP = append(endIP, network.IP[i]|^network.Mask[i])
	}

	// convert to big.Int
	endInt := big.NewInt(0)
	endInt.SetBytes(endIP)

	// subtract fromEnd from the last ip
	fromEndBig := big.NewInt(int64(fromEnd))
	resultInt := big.NewInt(0)
	resultInt.Sub(endInt, fromEndBig)

	return resultInt.Bytes()
}
