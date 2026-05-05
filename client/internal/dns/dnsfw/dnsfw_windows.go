//go:build windows

package dnsfw

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	modIphlpapi                    = windows.NewLazyDLL("iphlpapi.dll")
	procConvertInterfaceGuidToLuid = modIphlpapi.NewProc("ConvertInterfaceGuidToLuid")
)

type windowsManager struct {
	mu sync.Mutex
	// session is the WFP engine handle. Zero when disabled.
	session uintptr
}

// Enable installs the dns firewall. Strict mode propagates failures;
// non-strict mode logs and returns nil so partial protection is preserved.
func (m *windowsManager) Enable(ifaceGUID string, virtualDNSIP netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ports := blockedPorts()
	if len(ports) == 0 {
		return nil
	}

	if m.session != 0 {
		if err := m.disableLocked(); err != nil {
			return fmt.Errorf("reset existing dns firewall session: %w", err)
		}
	}

	strict := strictMode()

	luid, err := luidFromGUID(ifaceGUID)
	if err != nil {
		return m.failOrLog(strict, fmt.Errorf("resolve tun luid from guid %s: %w", ifaceGUID, err))
	}

	exe, err := os.Executable()
	if err != nil {
		return m.failOrLog(strict, fmt.Errorf("resolve daemon executable path: %w", err))
	}

	cfg := installConfig{
		tunLUID:      luid,
		daemonExe:    exe,
		blockedPorts: ports,
		strict:       strict,
		virtualDNSIP: virtualDNSIP,
	}
	// session==0 signals a hard failure; non-zero with non-nil err is a partial install.
	session, installErr := installFilters(cfg)
	if session == 0 {
		return m.failOrLog(strict, fmt.Errorf("install dns firewall filters: %w", installErr))
	}

	if installErr != nil && strict {
		_ = closeSession(session)
		return fmt.Errorf("strict dns firewall: partial install: %w", installErr)
	}

	m.session = session
	log.Infof("dns firewall installed: iface=%s daemon=%s ports=%v strict=%v virtual_dns=%s",
		ifaceGUID, exe, ports, strict, virtualDNSIP)
	if installErr != nil {
		log.Warnf("dns firewall partially installed (some filters failed): %v", installErr)
	}
	return nil
}

func (m *windowsManager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disableLocked()
}

func (m *windowsManager) disableLocked() error {
	if m.session == 0 {
		return nil
	}
	session := m.session
	m.session = 0
	if err := closeSession(session); err != nil {
		return fmt.Errorf("close wfp session: %w", err)
	}
	log.Info("dns firewall removed")
	return nil
}

// failOrLog returns err unchanged in strict mode. In non-strict mode the
// error is logged and nil is returned.
func (m *windowsManager) failOrLog(strict bool, err error) error {
	if strict {
		return err
	}
	log.Errorf("dns firewall: %v", err)
	return nil
}

// New returns a Windows DNS firewall manager backed by WFP.
func New() Manager {
	return &windowsManager{}
}

// strictMode reports whether strict mode is enabled via env.
func strictMode() bool {
	v, _ := strconv.ParseBool(os.Getenv(EnvStrict))
	return v
}

// luidFromGUID converts a Windows interface GUID string to its LUID.
func luidFromGUID(ifaceGUID string) (luid uint64, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in luidFromGUID: %v", r)
		}
	}()

	guid, err := windows.GUIDFromString(ifaceGUID)
	if err != nil {
		return 0, fmt.Errorf("parse guid: %w", err)
	}
	rc, _, _ := procConvertInterfaceGuidToLuid.Call(
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if rc != 0 {
		return 0, fmt.Errorf("ConvertInterfaceGuidToLuid returned %d", rc)
	}
	return luid, nil
}
