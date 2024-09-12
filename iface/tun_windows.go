package iface

import (
	"fmt"
	"net/netip"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/iface/bind"
)

const defaultWindowsGUIDSTring = "{f2f29e61-d91f-4d76-8151-119b20c4bdeb}"

type tunDevice struct {
	name    string
	address WGAddress
	port    int
	key     string
	mtu     int
	iceBind *bind.ICEBind

	device          *device.Device
	nativeTunDevice *tun.NativeTun
	wrapper         *DeviceWrapper
	udpMux          *bind.UniversalUDPMuxDefault
	configurer      wgConfigurer
}

func newTunDevice(name string, address WGAddress, port int, key string, mtu int, transportNet transport.Net, filterFn bind.FilterFn) wgTunDevice {
	return &tunDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		mtu:     mtu,
		iceBind: bind.NewICEBind(transportNet, filterFn),
	}
}

func getGUID() (windows.GUID, error) {
	guidString := defaultWindowsGUIDSTring
	if CustomWindowsGUIDString != "" {
		guidString = CustomWindowsGUIDString
	}
	return windows.GUIDFromString(guidString)
}

func (t *tunDevice) Create() (wgConfigurer, error) {
	guid, err := getGUID()
	if err != nil {
		log.Errorf("failed to get GUID: %s", err)
		return nil, err
	}
	log.Info("create tun interface")
	tunDevice, err := tun.CreateTUNWithRequestedGUID(t.name, &guid, t.mtu)
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %s", err)
	}
	t.nativeTunDevice = tunDevice.(*tun.NativeTun)
	t.wrapper = newDeviceWrapper(tunDevice)

	// We need to create a wireguard-go device and listen to configuration requests
	t.device = device.NewDevice(
		t.wrapper,
		t.iceBind,
		device.NewLogger(wgLogLevel(), "[netbird] "),
	)

	luid := winipcfg.LUID(t.nativeTunDevice.LUID())

	nbiface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		t.device.Close()
		return nil, fmt.Errorf("got error when getting ip interface %s", err)
	}

	nbiface.NLMTU = uint32(t.mtu)

	err = nbiface.Set()
	if err != nil {
		t.device.Close()
		return nil, fmt.Errorf("got error when getting setting the interface mtu: %s", err)
	}
	err = t.assignAddr()
	if err != nil {
		t.device.Close()
		return nil, fmt.Errorf("error assigning ip: %s", err)
	}

	t.configurer = newWGUSPConfigurer(t.device, t.name)
	err = t.configurer.configureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.close()
		return nil, fmt.Errorf("error configuring interface: %s", err)
	}
	return t.configurer, nil
}

func (t *tunDevice) Up() (*bind.UniversalUDPMuxDefault, error) {
	err := t.device.Up()
	if err != nil {
		return nil, err
	}

	udpMux, err := t.iceBind.GetICEMux()
	if err != nil {
		return nil, err
	}
	t.udpMux = udpMux
	log.Debugf("device is ready to use: %s", t.name)
	return udpMux, nil
}

func (t *tunDevice) UpdateAddr(address WGAddress) error {
	t.address = address
	return t.assignAddr()
}

func (t *tunDevice) Close() error {
	if t.configurer != nil {
		t.configurer.close()
	}

	if t.device != nil {
		t.device.Close()
		t.device = nil
	}

	if t.udpMux != nil {
		return t.udpMux.Close()

	}
	return nil
}
func (t *tunDevice) WgAddress() WGAddress {
	return t.address
}

func (t *tunDevice) DeviceName() string {
	return t.name
}

func (t *tunDevice) Wrapper() *DeviceWrapper {
	return t.wrapper
}

func (t *tunDevice) getInterfaceGUIDString() (string, error) {
	if t.nativeTunDevice == nil {
		return "", fmt.Errorf("interface has not been initialized yet")
	}

	luid := winipcfg.LUID(t.nativeTunDevice.LUID())
	guid, err := luid.GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (t *tunDevice) assignAddr() error {
	luid := winipcfg.LUID(t.nativeTunDevice.LUID())
	log.Debugf("adding address %s to interface: %s", t.address.IP, t.name)
	return luid.SetIPAddresses([]netip.Prefix{netip.MustParsePrefix(t.address.String())})
}
