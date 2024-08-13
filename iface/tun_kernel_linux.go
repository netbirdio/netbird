//go:build linux && !android

package iface

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/sharedsock"
)

type tunKernelDevice struct {
	name         string
	address      WGAddress
	address6     *WGAddress
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

func newTunDevice(name string, address WGAddress, address6 *WGAddress, wgPort int, key string, mtu int, transportNet transport.Net) wgTunDevice {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunKernelDevice{
		ctx:          ctx,
		ctxCancel:    cancel,
		name:         name,
		address:      address,
		address6:     address6,
		wgPort:       wgPort,
		key:          key,
		mtu:          mtu,
		transportNet: transportNet,
	}
}

func (t *tunKernelDevice) Create() (wgConfigurer, error) {
	link := newWGLink(t.name)

	// check if interface exists
	l, err := netlink.LinkByName(t.name)
	if err != nil {
		switch err.(type) {
		case netlink.LinkNotFoundError:
			break
		default:
			return nil, err
		}
	}

	// remove if interface exists
	if l != nil {
		err = netlink.LinkDel(link)
		if err != nil {
			return nil, err
		}
	}

	log.Debugf("adding device: %s", t.name)
	err = netlink.LinkAdd(link)
	if os.IsExist(err) {
		log.Infof("interface %s already exists. Will reuse.", t.name)
	} else if err != nil {
		return nil, err
	}

	t.link = link

	err = t.assignAddr()
	if err != nil {
		return nil, err
	}

	// todo do a discovery
	log.Debugf("setting MTU: %d interface: %s", t.mtu, t.name)
	err = netlink.LinkSetMTU(link, t.mtu)
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

	log.Debugf("bringing up interface: %s", t.name)
	err := netlink.LinkSetUp(t.link)
	if err != nil {
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

func (t *tunKernelDevice) UpdateAddr6(address6 *WGAddress) error {
	t.address6 = address6
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

func (t *tunKernelDevice) WgAddress6() *WGAddress {
	return t.address6
}

func (t *tunKernelDevice) DeviceName() string {
	return t.name
}

func (t *tunKernelDevice) Wrapper() *DeviceWrapper {
	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (t *tunKernelDevice) assignAddr() error {
	link := newWGLink(t.name)

	//delete existing addresses
	list, err := netlink.AddrList(link, 0)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		for _, a := range list {
			addr := a
			err = netlink.AddrDel(link, &addr)
			if err != nil {
				return err
			}
		}
	}

	log.Debugf("adding address %s to interface: %s", t.address.String(), t.name)
	addr, _ := netlink.ParseAddr(t.address.String())
	err = netlink.AddrAdd(link, addr)
	if os.IsExist(err) {
		log.Infof("interface %s already has the address: %s", t.name, t.address.String())
	} else if err != nil {
		return err
	}

	// Configure the optional additional IPv6 address if available.
	if t.address6 != nil {
		log.Debugf("adding IPv6 address %s to interface: %s", t.address6.String(), t.name)
		addr6, _ := netlink.ParseAddr(t.address6.String())
		err = netlink.AddrAdd(link, addr6)
		if os.IsExist(err) {
			log.Infof("interface %s already has the address: %s", t.name, t.address.String())
		} else if err != nil {
			return err
		}
	}

	// On linux, the link must be brought up
	err = netlink.LinkSetUp(link)
	return err
}
