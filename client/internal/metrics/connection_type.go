package metrics

// ConnectionType represents the type of peer connection
type ConnectionType string

const (
	// ConnectionTypeICE represents a direct peer-to-peer connection using ICE
	ConnectionTypeICE ConnectionType = "ice"

	// ConnectionTypeRelay represents a relayed connection
	ConnectionTypeRelay ConnectionType = "relay"
)

// String returns the string representation of the connection type
func (c ConnectionType) String() string {
	return string(c)
}
