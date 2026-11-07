//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// guidDevClassNet is the device setup class of network adapters.
var guidDevClassNet = windows.GUID{
	Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce,
	Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18},
}

// wintunHardwareID is the hardware ID of every wintun adapter.
const wintunHardwareID = "Wintun"

// removeLeftoverAdapter removes the wintun adapter a named installation's
// service left behind, for example after a crash, so a later installation of
// the same name starts clean (SBS-SVC-06). A running service removes its own
// adapter when it stops, so the adapter is only touched while the service is
// stopped or gone. The default installation is not changed.
func removeLeftoverAdapter(s service.Service) {
	inst := instance.Current()
	if inst.IsDefault() {
		return
	}
	status, err := s.Status()
	if err != nil && !errors.Is(err, service.ErrNotInstalled) {
		log.Warnf("leave the adapter of %s alone, the service state is unknown: %v", inst.Name(), err)
		return
	}
	if err == nil && status != service.StatusStopped {
		log.Infof("leave the adapter of %s alone, its service is still running", inst.Name())
		return
	}

	removed, err := removeAdapterByGUID(inst.AdapterGUID())
	switch {
	case err != nil:
		log.Warnf("remove the leftover adapter of %s: %v", inst.Name(), err)
	case removed:
		log.Infof("removed the leftover adapter %s of %s", inst.AdapterGUID(), inst.Name())
	}
}

// removeAdapterByGUID removes the wintun network device whose NetCfgInstanceId
// is guid, whether it is present or only left in the registry. It reports
// false when there is no such device.
func removeAdapterByGUID(guid string) (bool, error) {
	want, err := windows.GUIDFromString(guid)
	if err != nil {
		return false, fmt.Errorf("parse adapter GUID %q: %w", guid, err)
	}
	// No DIGCF_PRESENT: a device the crashed service left behind may be gone
	// from the bus but still registered.
	devs, err := windows.SetupDiGetClassDevsEx(&guidDevClassNet, "", 0, 0, 0, "")
	if err != nil {
		return false, fmt.Errorf("list network devices: %w", err)
	}
	defer func() {
		if err := devs.Close(); err != nil {
			log.Debugf("close the device list: %v", err)
		}
	}()

	for i := 0; ; i++ {
		data, err := devs.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return false, nil
		}
		if err != nil {
			continue
		}
		if !isWintunDevice(devs, data) || !hasNetCfgInstanceID(devs, data, want) {
			continue
		}
		if err := removeDevice(devs, data); err != nil {
			return false, err
		}
		return true, nil
	}
}

func isWintunDevice(devs windows.DevInfo, data *windows.DevInfoData) bool {
	ids, err := devs.DeviceRegistryProperty(data, windows.SPDRP_HARDWAREID)
	if err != nil {
		return false
	}
	return hasHardwareID(ids, wintunHardwareID)
}

// hasHardwareID reports whether a SPDRP_HARDWAREID value, a string list,
// contains id. Hardware IDs compare case-insensitively.
func hasHardwareID(value interface{}, id string) bool {
	ids, ok := value.([]string)
	if !ok {
		return false
	}
	for _, v := range ids {
		if strings.EqualFold(v, id) {
			return true
		}
	}
	return false
}

func hasNetCfgInstanceID(devs windows.DevInfo, data *windows.DevInfoData, want windows.GUID) bool {
	h, err := devs.OpenDevRegKey(data, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
	if err != nil {
		return false
	}
	key := registry.Key(h)
	defer func() {
		if err := key.Close(); err != nil {
			log.Debugf("close the driver key: %v", err)
		}
	}()
	value, _, err := key.GetStringValue("NetCfgInstanceId")
	if err != nil {
		return false
	}
	got, err := windows.GUIDFromString(value)
	return err == nil && got == want
}

func removeDevice(devs windows.DevInfo, data *windows.DevInfoData) error {
	params := windows.RemoveDeviceParams{
		ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE),
		Scope:              windows.DI_REMOVEDEVICE_GLOBAL,
	}
	if err := devs.SetClassInstallParams(data, &params.ClassInstallHeader, uint32(unsafe.Sizeof(params))); err != nil {
		return fmt.Errorf("set the removal parameters: %w", err)
	}
	if err := devs.CallClassInstaller(windows.DIF_REMOVE, data); err != nil {
		return fmt.Errorf("remove the device: %w", err)
	}
	return nil
}
