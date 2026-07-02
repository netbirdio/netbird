/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 NetBird GmbH. All Rights Reserved.
 *
 * Session lifecycle and the high-level Install/Close entry points adapted
 * from wireguard-windows tunnel/firewall.
 */

package dnsfw

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/sys/windows"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// installConfig is the input to installFilters.
type installConfig struct {
	tunLUID      uint64
	daemonExe    string
	blockedPorts []uint16
	// strict, when true, narrows the carve-out from "anything on tun" to
	// "DNS only to virtualDNSIP". virtualDNSIP must be valid in this case.
	strict       bool
	virtualDNSIP netip.Addr
}

// baseObjects holds the GUIDs of the WFP provider and sublayer registered
// for our session. Both are randomly generated per session.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// installFilters opens a dynamic WFP session and installs the netbird DNS
// firewall filters. Returns a zero session on hard failure (session create,
// base objects); a non-zero session with a non-nil error is a partial install
// (some per-filter installs failed) and is safe to close.
func installFilters(cfg installConfig) (session uintptr, err error) {
	defer func() {
		if r := recover(); r != nil {
			// Dynamic session: kernel will clean up on process exit even
			// if we leave the handle dangling here.
			err = fmt.Errorf("panic in installFilters: %v", r)
		}
	}()

	if len(cfg.blockedPorts) == 0 {
		return 0, errors.New("dns firewall: no blocked ports configured")
	}
	if cfg.strict && !cfg.virtualDNSIP.IsValid() {
		return 0, errors.New("dns firewall: strict mode requires a valid virtual DNS IP")
	}

	session, err = createSession()
	if err != nil {
		return 0, err
	}

	base, err := registerBaseObjects(session)
	if err != nil {
		_ = fwpmEngineClose0(session)
		return 0, fmt.Errorf("register base objects: %w", err)
	}

	var merr *multierror.Error
	if cfg.strict {
		if err := permitVirtualDNSIP(session, base, cfg.virtualDNSIP, cfg.blockedPorts, 15); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("permit virtual dns: %w", err))
		}
	} else {
		if err := permitTunInterface(session, base, 15, cfg.tunLUID); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("permit tun interface: %w", err))
		}
	}
	if err := permitDaemonByAppID(session, base, cfg.daemonExe, 14); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("permit netbird daemon: %w", err))
	}
	if err := blockDNSPorts(session, base, cfg.blockedPorts, 10); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("block dns ports: %w", err))
	}

	return session, nberrors.FormatErrorOrNil(merr)
}

// closeSession tears down a WFP session previously opened by installFilters.
// All filters owned by the session are removed.
func closeSession(session uintptr) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in closeSession: %v", r)
		}
	}()

	if session == 0 {
		return nil
	}
	if err := fwpmEngineClose0(session); err != nil {
		return wrapErr(err)
	}
	return nil
}

func createSession() (uintptr, error) {
	displayData, err := createWtFwpmDisplayData0("NetBird DNS firewall", "NetBird DNS firewall dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}
	session := wtFwpmSession0{
		displayData:          *displayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	var handle uintptr
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&handle)); err != nil {
		return 0, wrapErr(err)
	}
	return handle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	if bo.provider, err = windows.GenerateGUID(); err != nil {
		return nil, wrapErr(err)
	}
	if bo.filters, err = windows.GenerateGUID(); err != nil {
		return nil, wrapErr(err)
	}

	displayData, err := createWtFwpmDisplayData0("NetBird DNS firewall", "NetBird DNS firewall provider")
	if err != nil {
		return nil, wrapErr(err)
	}
	provider := wtFwpmProvider0{
		providerKey: bo.provider,
		displayData: *displayData,
	}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
		return nil, wrapErr(err)
	}

	subDisplay, err := createWtFwpmDisplayData0("NetBird DNS firewall filters", "Permit and block filters")
	if err != nil {
		return nil, wrapErr(err)
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *subDisplay,
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
		return nil, wrapErr(err)
	}
	return bo, nil
}

// daemonAppID returns the WFP App-ID byte blob for the given executable path.
func daemonAppID(path string) (*wtFwpByteBlob, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, wrapErr(err)
	}
	var appID *wtFwpByteBlob
	if err := fwpmGetAppIdFromFileName0(pathPtr, unsafe.Pointer(&appID)); err != nil {
		return nil, wrapErr(err)
	}
	return appID, nil
}
