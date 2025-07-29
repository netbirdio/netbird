//go:build (linux && !android) || freebsd

package device

import (
	"context"
	"fmt"
	"net"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/sharedsock"
)

type TunKernelDevice struct {
	name         string
	address      wgaddr.Address
	wgPort       int
	key          string
	mtu          int
	ctx          context.Context
	ctxCancel    context.CancelFunc
	transportNet transport.Net

	link       *wgLink
	udpMuxConn net.PacketConn
	udpMux     *bind.UniversalUDPMuxDefault

	filterFn bind.FilterFn
}

func NewKernelDevice(name string, address wgaddr.Address, wgPort int, key string, mtu int, transportNet transport.Net) *TunKernelDevice {
	ctx, cancel := context.WithCancel(context.Background())
	return &TunKernelDevice{
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

func (t *TunKernelDevice) Create() (WGConfigurer, error) {
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

	configurer := configurer.NewKernelConfigurer(t.name)

	if err := configurer.ConfigureInterface(t.key, t.wgPort); err != nil {
		return nil, fmt.Errorf("error configuring interface: %s", err)
	}

	return configurer, nil
}

func (t *TunKernelDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
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

	var udpConn net.PacketConn = rawSock
	if !nbnet.AdvancedRouting() {
		udpConn = nbnet.WrapPacketConn(rawSock)
	}

	bindParams := bind.UniversalUDPMuxParams{
		UDPConn:   udpConn,
		Net:       t.transportNet,
		FilterFn:  t.filterFn,
		WGAddress: t.address,
	}
	mux := bind.NewUniversalUDPMuxDefault(bindParams)
	go mux.ReadFromConn(t.ctx)
	t.udpMuxConn = rawSock
	t.udpMux = mux

	log.Debugf("device is ready to use: %s", t.name)
	return t.udpMux, nil
}

func (t *TunKernelDevice) UpdateAddr(address wgaddr.Address) error {
	t.address = address
	return t.assignAddr()
}

func (t *TunKernelDevice) Close() error {
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

func (t *TunKernelDevice) WgAddress() wgaddr.Address {
	return t.address
}

func (t *TunKernelDevice) DeviceName() string {
	return t.name
}

// Device returns the wireguard device, not applicable for kernel devices
func (t *TunKernelDevice) Device() *device.Device {
	return nil
}

func (t *TunKernelDevice) FilteredDevice() *FilteredDevice {
	return nil
}

// assignAddr Adds IP address to the tunnel interface
func (t *TunKernelDevice) assignAddr() error {
	return t.link.assignAddr(t.address)
}

func (t *TunKernelDevice) GetNet() *netstack.Net {
	return nil
}
