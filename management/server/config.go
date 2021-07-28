package server

type ConfigProto int

const (
	UDP ConfigProto = iota + 1
	TCP
	TCPWithTLS
	UDPWithTLS
)

// Config of the Management service
type Config struct {
	Stuns  []*Host
	Turns  []*Host
	Signal *Host

	Datadir           string
	LetsEncryptDomain string
}

// Host represents a Wiretrustee host (e.g. STUN, TURN, Signal)
type Host struct {
	Proto    ConfigProto
	Host     string
	Port     int32
	Username string
	Password []byte
}
