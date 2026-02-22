package device

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"

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

const (
	wintunServiceName         = "wintun"
	wintunDriverRecoveryWait  = 2 * time.Second
	wintunRecoveryTimeout     = 15 * time.Second
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
		if isWintunDriverError(err) {
			log.Warnf("TUN creation failed with wintun driver error, attempting recovery: %s", err)
			if recoverErr := tryRecoverWintunDriver(); recoverErr != nil {
				log.Warnf("wintun driver recovery failed: %s", recoverErr)
			} else {
				log.Info("wintun driver recovery completed, retrying TUN creation")
				tunDevice, err = tun.CreateTUNWithRequestedGUID(t.name, &guid, int(t.mtu))
			}
		}
		if err != nil {
			return nil, fmt.Errorf("error creating tun device: %s", err)
		}
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
		return nil, fmt.Errorf("got error when getting setting the interface mtu: %s", err)
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
	log.Debugf("adding address %s to interface: %s", t.address.IP, t.name)
	return luid.SetIPAddresses([]netip.Prefix{netip.MustParsePrefix(t.address.String())})
}

func (t *TunDevice) GetNet() *netstack.Net {
	return nil
}

// GetICEBind returns the ICEBind instance
func (t *TunDevice) GetICEBind() EndpointManager {
	return t.iceBind
}

// isWintunDriverError checks whether the TUN creation error indicates a stale
// or broken wintun kernel driver registration. This typically manifests as
// ERROR_FILE_NOT_FOUND (syscall.Errno 2) when the driver entry in the
// Windows service registry is present but the driver fails to load (e.g.,
// after a Windows update changes the kernel ABI).
func isWintunDriverError(err error) bool {
	if err == nil {
		return false
	}
	// Prefer precise errno check when available
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ERROR_FILE_NOT_FOUND
	}
	// Fallback: string match for wrapped errors that lost the Errno type
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "the system cannot find the file specified")
}

// tryRecoverWintunDriver attempts to recover from a broken wintun kernel driver
// registration by removing the stale service entry. The wintun library will
// automatically re-install the driver on the next CreateTUN call.
//
// This addresses a known issue where the wintun driver entry becomes stale
// after Windows updates (especially on Windows 11 Insider builds), causing
// the driver to fail with ERROR_GEN_FAILURE (error 31). Removing the stale
// entry allows re-registration with the current kernel.
//
// Requires administrator privileges, which are available when running as the
// NetBird Windows service (LocalSystem account).
//
// See: https://github.com/netbirdio/netbird/issues/5408
func tryRecoverWintunDriver() error {
	scCmd := getSystem32Command("sc.exe")

	ctx, cancel := context.WithTimeout(context.Background(), wintunRecoveryTimeout)
	defer cancel()

	// Check current wintun driver state before taking action
	out, err := exec.CommandContext(ctx, scCmd, "query", wintunServiceName).CombinedOutput()
	if err != nil {
		outStr := strings.ToLower(string(out))
		// Exit code 1060 / "failed 1060" means the service does not exist —
		// nothing to recover, let wintun re-create it on next attempt.
		if strings.Contains(outStr, "1060") {
			log.Debugf("%s service not found, skipping recovery", wintunServiceName)
			return nil
		}
		return fmt.Errorf("failed to query %s service: %w (output: %s)", wintunServiceName, err, string(out))
	}

	outStr := strings.ToLower(string(out))

	// Only proceed if the driver is stopped (not running)
	if strings.Contains(outStr, "running") {
		return fmt.Errorf("%s driver is running, recovery not applicable", wintunServiceName)
	}

	log.Warnf("%s driver is in a failed state, removing stale service entry for re-registration", wintunServiceName)

	out, err = exec.CommandContext(ctx, scCmd, "delete", wintunServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete %s service: %w (output: %s)", wintunServiceName, err, string(out))
	}

	log.Infof("stale %s service entry removed, waiting for cleanup", wintunServiceName)
	time.Sleep(wintunDriverRecoveryWait)

	return nil
}

// getSystem32Command returns the full path to a System32 command if it cannot
// be found on PATH. This mirrors the pattern used in the iface package.
func getSystem32Command(command string) string {
	_, err := exec.LookPath(command)
	if err == nil {
		return command
	}
	return `C:\windows\system32\` + command
}
