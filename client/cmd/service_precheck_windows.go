//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/internal/instance"
)

var procGetServiceKeyNameW = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetServiceKeyNameW")

// checkNamedServiceFree fails before anything is written when the service name
// or display name of a named installation is taken. The service library writes
// the service's Environment value before it notices that the service exists, so
// a second install under the same name would otherwise change the first one's
// registration. The default installation keeps today's behaviour.
func checkNamedServiceFree() error {
	inst := instance.Current()
	if inst.IsDefault() {
		return nil
	}

	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("open service control manager: %w", err)
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()

	if err := checkServiceNameFree(scm, serviceName); err != nil {
		return err
	}
	return checkDisplayNameFree(scm, inst.ServiceDisplayName())
}

func checkServiceNameFree(scm windows.Handle, name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("service name %q: %w", name, err)
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS)
	if err == nil {
		_ = windows.CloseServiceHandle(h)
		return fmt.Errorf("service %s already exists; uninstall it first", name)
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	return fmt.Errorf("check service %s: %w", name, err)
}

func checkDisplayNameFree(scm windows.Handle, display string) error {
	displayPtr, err := windows.UTF16PtrFromString(display)
	if err != nil {
		return fmt.Errorf("service display name %q: %w", display, err)
	}
	buf := make([]uint16, 257)
	size := uint32(len(buf))
	r, _, callErr := procGetServiceKeyNameW.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(displayPtr)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r != 0 {
		return fmt.Errorf("service display name %q is already used by service %s", display, windows.UTF16ToString(buf))
	}
	if errors.Is(callErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	// Any other failure leaves the question open: refuse rather than risk
	// writing over another service's registration.
	return fmt.Errorf("check service display name %q: %w", display, callErr)
}
