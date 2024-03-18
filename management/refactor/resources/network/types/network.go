package types

import (
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/c-robinson/iplib"
	"github.com/rs/xid"
)

const (
	// SubnetSize is a size of the subnet of the global network, e.g.  100.77.0.0/16
	SubnetSize = 16
	// NetSize is a global network size 100.64.0.0/10
	NetSize = 10
)

type Network struct {
	Identifier string    `json:"id"`
	Net        net.IPNet `gorm:"serializer:gob"`
	Dns        string
	// Serial is an ID that increments by 1 when any change to the network happened (e.g. new peer has been added).
	// Used to synchronize state to the client apps.
	Serial uint64

	mu sync.Mutex `json:"-" gorm:"-"`
}

// NewNetwork creates a new Network initializing it with a Serial=0
// It takes a random /16 subnet from 100.64.0.0/10 (64 different subnets)
func NewNetwork() *Network {

	n := iplib.NewNet4(net.ParseIP("100.64.0.0"), NetSize)
	sub, _ := n.Subnet(SubnetSize)

	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)
	intn := r.Intn(len(sub))

	return &Network{
		Identifier: xid.New().String(),
		Net:        sub[intn].IPNet,
		Dns:        "",
		Serial:     0}
}

// IncSerial increments Serial by 1 reflecting that the network state has been changed
func (n *Network) IncSerial() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Serial++
}

// CurrentSerial returns the Network.Serial of the network (latest state id)
func (n *Network) CurrentSerial() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Serial
}

func (n *Network) Copy() *Network {
	return &Network{
		Identifier: n.Identifier,
		Net:        n.Net,
		Dns:        n.Dns,
		Serial:     n.Serial,
	}
}
