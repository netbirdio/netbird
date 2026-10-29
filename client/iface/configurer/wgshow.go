package configurer

import (
	"net"
	"time"
)

type Peer struct {
	PublicKey     string
	Endpoint      net.UDPAddr
	AllowedIPs    []net.IPNet
	TxBytes       int64
	RxBytes       int64
	LastHandshake time.Time
	PresharedKey  [32]byte
}

type Stats struct {
	DeviceName string
	PublicKey  string
	ListenPort int
	FWMark     int
	Peers      []Peer
}
