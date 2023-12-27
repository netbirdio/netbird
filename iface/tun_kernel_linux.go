//go:build linux && !android

package iface

import (
	"context"
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
	wgPort       int
	mtu          int
	ctx          context.Context
	transportNet transport.Net

	link       *wgLink
	udpMuxConn net.PacketConn
	udpMux     *bind.UniversalUDPMuxDefault
}

func newTunDevice(ctx context.Context, name string, address WGAddress, wgPort int, mtu int, transportNet transport.Net) wgTunDevice {
	return &tunKernelDevice{
		ctx:          ctx,
		name:         name,
		address:      address,
		wgPort:       wgPort,
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

	log.Debugf("bringing up interface: %s", t.name)
	err = netlink.LinkSetUp(link)
	if err != nil {
		_ = link.Close()
		log.Errorf("error bringing up interface: %s", t.name)
		return nil, err
	}

	rawSock, err := sharedsock.Listen(t.wgPort, sharedsock.NewIncomingSTUNFilter())
	if err != nil {
		_ = link.Close()
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

	configurer := newWGConfigurer(t.name)
	return configurer, nil
}

func (t *tunKernelDevice) UpdateAddr(address WGAddress) error {
	t.address = address
	return t.assignAddr()
}

func (t *tunKernelDevice) Close() error {
	if t.link == nil {
		return nil
	}

	var closErr error
	if err := t.link.Close(); err != nil {
		log.Debugf("failed to close link: %s", err)
		closErr = err
	}

	if err := t.udpMux.Close(); err != nil {
		log.Debugf("failed to close udp mux: %s", err)
		closErr = err
	}

	if err := t.udpMuxConn.Close(); err != nil {
		log.Debugf("failed to close udp mux connection: %s", err)
		closErr = err
	}

	return closErr
}

func (t *tunKernelDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunKernelDevice) DeviceName() string {
	return t.name
}

func (t *tunKernelDevice) IceBind() *bind.ICEBind {
	return nil
}

func (t *tunKernelDevice) Wrapper() *DeviceWrapper {
	return nil
}

func (t *tunKernelDevice) UdpMux() *bind.UniversalUDPMuxDefault {
	return t.udpMux
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
	// On linux, the link must be brought up
	err = netlink.LinkSetUp(link)
	return err
}
