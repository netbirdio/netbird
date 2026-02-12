package device

import (
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	nbnetstack "github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbnet "github.com/netbirdio/netbird/client/net"
)

type Bind interface {
	conn.Bind
	GetICEMux() (*udpmux.UniversalUDPMuxDefault, error)
	ActivityRecorder() *bind.ActivityRecorder
	EndpointManager
}

type TunNetstackDevice struct {
	name          string
	address       wgaddr.Address
	port          int
	key           string
	mtu           uint16
	listenAddress string
	bind          Bind

	device         *device.Device
	filteredDevice *FilteredDevice
	nsTun          *nbnetstack.NetStackTun
	udpMux         *udpmux.UniversalUDPMuxDefault
	configurer     WGConfigurer

	net *netstack.Net
}

func NewNetstackDevice(name string, address wgaddr.Address, wgPort int, key string, mtu uint16, bind Bind, listenAddress string) *TunNetstackDevice {
	return &TunNetstackDevice{
		name:          name,
		address:       address,
		port:          wgPort,
		key:           key,
		mtu:           mtu,
		listenAddress: listenAddress,
		bind:          bind,
	}
}

func (t *TunNetstackDevice) create() (WGConfigurer, error) {
	log.Info("create nbnetstack tun interface")

	// TODO: get from service listener runtime IP
	dnsAddr, err := nbnet.GetLastIPFromNetwork(t.address.Network, 1)
	if err != nil {
		return nil, fmt.Errorf("last ip: %w", err)
	}

	log.Debugf("netstack using address: %s", t.address.IP)
	t.nsTun = nbnetstack.NewNetStackTun(t.listenAddress, t.address.IP, dnsAddr, int(t.mtu))
	log.Debugf("netstack using dns address: %s", dnsAddr)
	tunIface, net, err := t.nsTun.Create()
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %s", err)
	}
	t.filteredDevice = newDeviceFilter(tunIface)
	t.net = net

	t.device = device.NewDevice(
		t.filteredDevice,
		t.bind,
		device.NewLogger(wgLogLevel(), "[netbird] "),
	)

	t.configurer = configurer.NewUSPConfigurer(t.device, t.name, t.bind.ActivityRecorder())
	err = t.configurer.ConfigureInterface(t.key, t.port)
	if err != nil {
		if cErr := tunIface.Close(); cErr != nil {
			log.Debugf("failed to close tun device: %v", cErr)
		}
		return nil, fmt.Errorf("error configuring interface: %s", err)
	}

	log.Debugf("device has been created: %s", t.name)
	return t.configurer, nil
}

func (t *TunNetstackDevice) Up() (*udpmux.UniversalUDPMuxDefault, error) {
	if t.device == nil {
		return nil, fmt.Errorf("device is not ready yet")
	}

	err := t.device.Up()
	if err != nil {
		return nil, err
	}

	udpMux, err := t.bind.GetICEMux()
	if err != nil && !errors.Is(err, bind.ErrUDPMUXNotSupported) {
		return nil, err
	}

	if udpMux != nil {
		t.udpMux = udpMux
	}

	log.Debugf("netstack device is ready to use")
	return udpMux, nil
}

func (t *TunNetstackDevice) UpdateAddr(wgaddr.Address) error {
	return nil
}

func (t *TunNetstackDevice) Close() error {
	if t.configurer != nil {
		t.configurer.Close()
	}

	if t.device != nil {
		t.device.Close()
	}

	if t.udpMux != nil {
		return t.udpMux.Close()
	}
	return nil
}

func (t *TunNetstackDevice) WgAddress() wgaddr.Address {
	return t.address
}

func (t *TunNetstackDevice) MTU() uint16 {
	return t.mtu
}

func (t *TunNetstackDevice) DeviceName() string {
	return t.name
}

func (t *TunNetstackDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}

// Device returns the wireguard device
func (t *TunNetstackDevice) Device() *device.Device {
	return t.device
}

func (t *TunNetstackDevice) GetNet() *netstack.Net {
	return t.net
}

// GetICEBind returns the bind instance
func (t *TunNetstackDevice) GetICEBind() EndpointManager {
	return t.bind
}
