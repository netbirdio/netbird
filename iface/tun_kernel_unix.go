//go:build (linux && !android) || freebsd

package iface

import (
	"context"
	"fmt"
	"net"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/sharedsock"
)

type tunKernelDevice struct {
	name         string
	address      WGAddress
	wgPort       int
	key          string
	mtu          int
	ctx          context.Context
	ctxCancel    context.CancelFunc
	transportNet transport.Net

	link       *wgLink
	udpMuxConn net.PacketConn
	udpMux     *bind.UniversalUDPMuxDefault
}

func newTunDevice(name string, address WGAddress, wgPort int, key string, mtu int, transportNet transport.Net) wgTunDevice {
	checkUser()

	ctx, cancel := context.WithCancel(context.Background())
	return &tunKernelDevice{
		ctx:          ctx,
		ctxCancel:    cancel,
		name:         name,
		address:      address,
		wgPort:       wgPort,
		key:          key,
		mtu:          mtu,
		transportNet: transportNet,
	}
}

func (t *tunKernelDevice) Create() (wgConfigurer, error) {
	link := newWGLink(t.name)

	if err := link.recreate(); err != nil {
		return nil, fmt.Errorf("recreate: %w", err)
	}

	t.link = link

	if err := t.assignAddr(); err != nil {
		return nil, fmt.Errorf("assign addr: %w", err)
	}

	// TODO: do a MTU discovery
	log.Debugf("setting MTU: %d interface: %s", t.mtu, t.name)

	if err := link.setMTU(t.mtu); err != nil {
		return nil, fmt.Errorf("set mtu: %w", err)
	}

	configurer := newWGConfigurer(t.name)

	if err := configurer.configureInterface(t.key, t.wgPort); err != nil {
		return nil, err
	}

	return configurer, nil
}

func (t *tunKernelDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
	if t.udpMux != nil {
		return t.udpMux, nil
	}

	if t.link == nil {
		return nil, fmt.Errorf("device is not ready yet")
	}

	log.Debugf("bringing up interface: %s", t.name)

	if err := t.link.up(); err != nil {
		log.Errorf("error bringing up interface: %s", t.name)

		return nil, err
	}

	rawSock, err := sharedsock.Listen(t.wgPort, sharedsock.NewIncomingSTUNFilter())
	if err != nil {
		return nil, err
	}
	bindParams := bind.UniversalUDPMuxParams{
		UDPConn: rawSock,
		Net:     t.transportNet,
	}
	mux := bind.NewUniversalUDPMuxDefault(bindParams)
	go mux.ReadFromConn(t.ctx)
	t.udpMuxConn = rawSock
	t.udpMux = mux

	log.Debugf("device is ready to use: %s", t.name)
	return t.udpMux, nil
}

func (t *tunKernelDevice) UpdateAddr(address WGAddress) error {
	t.address = address
	return t.assignAddr()
}

func (t *tunKernelDevice) Close() error {
	if t.link == nil {
		return nil
	}

	t.ctxCancel()

	var closErr error
	if err := t.link.Close(); err != nil {
		log.Debugf("failed to close link: %s", err)
		closErr = err
	}

	if t.udpMux != nil {
		if err := t.udpMux.Close(); err != nil {
			log.Debugf("failed to close udp mux: %s", err)
			closErr = err
		}

		if err := t.udpMuxConn.Close(); err != nil {
			log.Debugf("failed to close udp mux connection: %s", err)
			closErr = err
		}
	}

	return closErr
}

func (t *tunKernelDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunKernelDevice) DeviceName() string {
	return t.name
}

func (t *tunKernelDevice) Wrapper() *DeviceWrapper {
	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (t *tunKernelDevice) assignAddr() error {
	return t.link.assignAddr(t.address)
}
