package server

type ConfigProto int

const (
	UDP ConfigProto = iota + 1
	TCP
	TCPWithTLS
	UDPWithTLS
)

// HostsConfig specifies properties of the Wiretrustee services essential for the communication between peers.
// These properties will be sent to peers.
// These properties DO NOT configure anything in the Management service
type HostsConfig struct {
	Stuns  []*Host
	Turns  []*Host
	Signal *Host
}

// Host represents a Wiretrustee host (e.g. STUN, TURN, Signal)
type Host struct {
	Proto    ConfigProto
	Host     string
	Port     int32
	Username string
	Password []byte
}
