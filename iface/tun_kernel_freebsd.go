//go:build freebsd

package iface

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/iface/freebsd"
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

	link       *freebsd.Link
	udpMuxConn net.PacketConn
	udpMux     *bind.UniversalUDPMuxDefault
}

func newTunDevice(name string, address WGAddress, wgPort int, key string, mtu int, transportNet transport.Net) wgTunDevice {
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
	// Get the effective user ID
	euid := os.Geteuid()
	// Check if the effective user ID is 0 (root)
	if euid != 0 {
		return nil, fmt.Errorf("netbird must run as root on FreeBSD to be able to create wg interface")
	}

	link := freebsd.NewLink(t.name)

	// FIXME: debug
	fmt.Printf("TUN DEBUG: netlink creating...\n")

	err := link.Recreate()
	if err != nil {
		return nil, fmt.Errorf("recreate: %w", err)
	}

	t.link = link

	err = t.assignAddr()
	if err != nil {
		return nil, err
	}

	// todo do a discovery
	log.Debugf("setting MTU: %d interface: %s", t.mtu, t.name)
	err = link.SetMTU(t.mtu)
	if err != nil {
		log.Errorf("error setting MTU on interface: %s", t.name)
		return nil, err
	}

	configurer := newWGConfigurer(t.name)
	err = configurer.configureInterface(t.key, t.wgPort)
	if err != nil {
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

	// log.Debugf("bringing up interface: %s", t.name)
	// err := netlink.LinkSetUp(t.link)
	// if err != nil {
	// 	log.Errorf("error bringing up interface: %s", t.name)
	// 	return nil, err
	// }

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
	if err := t.link.Del(); err != nil {
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
	ip := t.address.IP.String()
	mask := t.address.Network.Mask.String()

	err := t.link.AssignAddr(ip, mask)
	if err != nil {
		// FIXME: debug
		log.Errorf("error setting MTU on interface: %s", t.name)
		return fmt.Errorf("assign addr: %w", err)
	}

	return nil
}
