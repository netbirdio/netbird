package management

// Account represents a unique account of the system
type Account struct {
	Id        string
	SetupKeys map[string]*SetupKey
	Peers     map[string]*Peer
}

// SetupKey represents a pre-authorized key used to register machines (peers)
// One key might have multiple machines
type SetupKey struct {
	Key string
}

// Peer represents a machine connected to the network.
// The Peer is a Wireguard peer identified by a public key
type Peer struct {
	// Wireguard public key
	Key string
	// A setup key this peer was registered with
	SetupKey *SetupKey
}

type Store interface {
	AddPeer(setupKey string, peerKey string) error
    GetPeersForAPeer(peerKey string) []string
}
