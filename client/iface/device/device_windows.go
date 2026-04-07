package device

import (
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const defaultWindowsGUIDSTring = "{f2f29e61-d91f-4d76-8151-119b20c4bdeb}"

type TunDevice struct {
	name    string
	address wgaddr.Address
	port    int
	key     string
	mtu     uint16
	iceBind *bind.ICEBind

	device          *device.Device
	nativeTunDevice *tun.NativeTun
	filteredDevice  *FilteredDevice
	udpMux          *udpmux.UniversalUDPMuxDefault
	configurer      WGConfigurer
}

func NewTunDevice(name string, address wgaddr.Address, port int, key string, mtu uint16, iceBind *bind.ICEBind) *TunDevice {
	return &TunDevice{
		name:    name,
		address: address,
		port:    port,
		key:     key,
		mtu:     mtu,
		iceBind: iceBind,
	}
}

func getGUID() (windows.GUID, error) {
	guidString := defaultWindowsGUIDSTring
	if CustomWindowsGUIDString != "" {
		guidString = CustomWindowsGUIDString
	}
	return windows.GUIDFromString(guidString)
}

func (t *TunDevice) Create() (WGConfigurer, error) {
	guid, err := getGUID()
	if err != nil {
		log.Errorf("failed to get GUID: %s", err)
		return nil, err
	}
	log.Info("create tun interface")
	tunDevice, err := tun.CreateTUNWithRequestedGUID(t.name, &guid, int(t.mtu))
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %s", err)
	}
	t.nativeTunDevice = tunDevice.(*tun.NativeTun)
	t.filteredDevice = newDeviceFilter(tunDevice)

	// We need to create a wireguard-go device and listen to configuration requests
	t.device = device.NewDevice(
		t.filteredDevice,
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
		return nil, fmt.Errorf("set IPv4 interface MTU: %s", err)
	}

	if t.address.HasIPv6() {
		nbiface6, err := luid.IPInterface(windows.AF_INET6)
		if err != nil {
			log.Warnf("failed to get IPv6 interface for MTU: %v", err)
		} else {
			nbiface6.NLMTU = uint32(t.mtu)
			if err := nbiface6.Set(); err != nil {
				log.Warnf("failed to set IPv6 interface MTU: %v", err)
			}
		}
	}
	err = t.assignAddr()
	if err != nil {
		t.device.Close()
		return nil, fmt.Errorf("error assigning ip: %s", err)
	}

	t.configurer = configurer.NewUSPConfigurer(t.device, t.name, t.iceBind.ActivityRecorder())
	err = t.configurer.ConfigureInterface(t.key, t.port)
	if err != nil {
		t.device.Close()
		t.configurer.Close()
		return nil, fmt.Errorf("error configuring interface: %s", err)
	}
	return t.configurer, nil
}

func (t *TunDevice) Up() (*udpmux.UniversalUDPMuxDefault, error) {
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

func (t *TunDevice) UpdateAddr(address wgaddr.Address) error {
	t.address = address
	return t.assignAddr()
}

func (t *TunDevice) Close() error {
	if t.configurer != nil {
		t.configurer.Close()
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
func (t *TunDevice) WgAddress() wgaddr.Address {
	return t.address
}

func (t *TunDevice) MTU() uint16 {
	return t.mtu
}

func (t *TunDevice) DeviceName() string {
	return t.name
}

func (t *TunDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}

// Device returns the wireguard device
func (t *TunDevice) Device() *device.Device {
	return t.device
}

func (t *TunDevice) GetInterfaceGUIDString() (string, error) {
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
func (t *TunDevice) assignAddr() error {
	luid := winipcfg.LUID(t.nativeTunDevice.LUID())

	v4Prefix := t.address.Prefix()
	if t.address.HasIPv6() {
		v6Prefix := t.address.IPv6Prefix()
		log.Debugf("adding addresses %s, %s to interface: %s", v4Prefix, v6Prefix, t.name)
		if err := luid.SetIPAddresses([]netip.Prefix{v4Prefix, v6Prefix}); err != nil {
			log.Warnf("failed to assign dual-stack addresses, retrying v4-only: %v", err)
			t.address.ClearIPv6()
			return luid.SetIPAddresses([]netip.Prefix{v4Prefix})
		}
		return nil
	}

	log.Debugf("adding address %s to interface: %s", v4Prefix, t.name)
	return luid.SetIPAddresses([]netip.Prefix{v4Prefix})
}

func (t *TunDevice) GetNet() *netstack.Net {
	return nil
}

// GetICEBind returns the ICEBind instance
func (t *TunDevice) GetICEBind() EndpointManager {
	return t.iceBind
}
