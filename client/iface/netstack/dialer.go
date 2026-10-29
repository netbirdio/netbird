package netstack

import (
	"context"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

type Dialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

type NSDialer struct {
	net *wgbackend.NetstackNet
}

func NewNSDialer(net *wgbackend.NetstackNet) *NSDialer {
	return &NSDialer{
		net: net,
	}
}

func (d *NSDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	log.Debugf("dialing %s %s", network, addr)
	conn, err := d.net.Dial(network, addr)
	if err != nil {
		log.Debugf("failed to deal connection: %s", err)
	}
	return conn, err
}
