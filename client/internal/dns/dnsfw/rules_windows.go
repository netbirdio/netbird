/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 NetBird GmbH. All Rights Reserved.
 *
 * Filter installers adapted from wireguard-windows tunnel/firewall/rules.go.
 * The block-DNS approach (port 53 + UDP/TCP) matches what wireguard-windows
 * uses for its kill-switch DNS leak protection. We extend it with a
 * configurable port set so we also cover :853 (DoT) and any future ports.
 */

package dnsfw

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/sys/windows"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// Filters install at outbound ALE_AUTH_CONNECT layers only; inbound replies
// follow the authorized outbound flow.

// permitTunInterface installs a permit filter for any traffic whose local
// interface is the netbird tunnel.
func permitTunInterface(session uintptr, base *baseObjects, weight uint8, ifLUID uint64) error {
	cond := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: uintptr(unsafe.Pointer(&ifLUID)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &base.provider,
		subLayerKey:         base.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&cond)),
		action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
	}

	return addOutboundFilters(session, &filter, "Permit netbird tunnel")
}

// permitDaemonByAppID installs a permit filter matching the netbird daemon
// executable by App-ID. App-ID alone is sufficient because netbird.exe is a
// dedicated binary.
func permitDaemonByAppID(session uintptr, base *baseObjects, daemonExe string, weight uint8) error {
	appID, err := daemonAppID(daemonExe)
	if err != nil {
		return err
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	cond := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &base.provider,
		subLayerKey:         base.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&cond)),
		action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
	}

	return addOutboundFilters(session, &filter, "Permit netbird daemon")
}

// permitVirtualDNSIP installs a permit filter for DNS-port traffic destined
// for the in-tunnel virtual DNS IP. Used in strict mode in lieu of
// permitTunInterface.
func permitVirtualDNSIP(session uintptr, base *baseObjects, ip netip.Addr, ports []uint16, weight uint8) error {
	var merr *multierror.Error
	for _, port := range ports {
		if err := permitDNSToHost(session, base, ip, port, weight); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("permit %s:%d: %w", ip, port, err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func permitDNSToHost(session uintptr, base *baseObjects, ip netip.Addr, port uint16, weight uint8) error {
	if !ip.IsValid() {
		return fmt.Errorf("invalid address")
	}

	var addrCond wtFwpmFilterCondition0
	var layer windows.GUID
	// v6 backing must outlive fwpmFilterAdd0; keep it on this stack frame.
	var v6 wtFwpByteArray16

	if ip.Is4() {
		v4 := ip.As4()
		addrCond = wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT32,
				value: uintptr(binary.BigEndian.Uint32(v4[:])),
			},
		}
		layer = cFWPM_LAYER_ALE_AUTH_CONNECT_V4
	} else {
		v6 = wtFwpByteArray16{byteArray16: ip.As16()}
		addrCond = wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_BYTE_ARRAY16_TYPE,
				value: uintptr(unsafe.Pointer(&v6)),
			},
		}
		layer = cFWPM_LAYER_ALE_AUTH_CONNECT_V6
	}

	conditions := [2]wtFwpmFilterCondition0{
		addrCond,
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(port),
			},
		},
	}
	filter := wtFwpmFilter0{
		providerKey:         &base.provider,
		subLayerKey:         base.filters,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
		action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
	}

	display, err := createWtFwpmDisplayData0(fmt.Sprintf("Permit DNS to %s:%d", ip, port), "")
	if err != nil {
		return wrapErr(err)
	}
	filter.displayData = *display
	filter.layerKey = layer

	var filterID uint64
	if err := fwpmFilterAdd0(session, &filter, 0, &filterID); err != nil {
		return wrapErr(err)
	}
	_ = v6
	return nil
}

// blockDNSPorts installs a deny filter for outbound traffic to each of the
// given remote ports over UDP or TCP. Per-port and per-layer failures are
// accumulated; partial coverage is preferred over zero coverage.
func blockDNSPorts(session uintptr, base *baseObjects, ports []uint16, weight uint8) error {
	var merr *multierror.Error
	for _, port := range ports {
		if err := blockDNSPort(session, base, port, weight); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("block port %d: %w", port, err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func blockDNSPort(session uintptr, base *baseObjects, port uint16, weight uint8) error {
	conditions := [3]wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(port),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_UDP),
			},
		},
		// Repeat the IP_PROTOCOL condition for logical OR with TCP.
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_TCP),
			},
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &base.provider,
		subLayerKey:         base.filters,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
		action:              wtFwpmAction0{_type: cFWP_ACTION_BLOCK},
	}

	return addOutboundFilters(session, &filter, fmt.Sprintf("Block DNS port %d", port))
}

// addOutboundFilters installs the same filter on the v4 and v6 outbound ALE
// connect layers. v4 and v6 are installed independently: failure on one
// layer does not abort the other, and the accumulated errors are returned.
// Partial coverage is preferred over zero coverage.
func addOutboundFilters(session uintptr, filter *wtFwpmFilter0, name string) error {
	layers := [...]struct {
		layer windows.GUID
		label string
	}{
		{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, name + " (IPv4)"},
		{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, name + " (IPv6)"},
	}

	var merr *multierror.Error
	for _, l := range layers {
		display, err := createWtFwpmDisplayData0(l.label, "")
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", l.label, wrapErr(err)))
			continue
		}
		filter.displayData = *display
		filter.layerKey = l.layer

		var filterID uint64
		if err := fwpmFilterAdd0(session, filter, 0, &filterID); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", l.label, wrapErr(err)))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}
