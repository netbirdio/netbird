package metrics

// ConnectionType represents the type of peer connection
type ConnectionType string

const (
	// ConnectionTypeICEP2P represents a direct peer-to-peer connection using ICE
	ConnectionTypeICEP2P ConnectionType = "ice_p2p"

	// ConnectionTypeICETurn represents an ICE connection through a TURN server
	ConnectionTypeICETurn ConnectionType = "ice_turn"

	// ConnectionTypeRelay represents a relayed connection
	ConnectionTypeRelay ConnectionType = "relay"

	// ConnectionTypeUnknown represents a connection with no active transport. It is not pushed.
	ConnectionTypeUnknown ConnectionType = "unknown"
)

// String returns the string representation of the connection type
func (c ConnectionType) String() string {
	return string(c)
}
