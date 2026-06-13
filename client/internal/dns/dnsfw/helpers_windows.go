/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 *
 * Adapted from wireguard-windows tunnel/firewall/helpers.go.
 */

package dnsfw

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

func createWtFwpmDisplayData0(name, description string) (*wtFwpmDisplayData0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, wrapErr(err)
	}

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, wrapErr(err)
	}

	return &wtFwpmDisplayData0{
		name:        namePtr,
		description: descriptionPtr,
	}, nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}

func wrapErr(err error) error {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return err
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("wfp error at unknown location: %w", err)
	}
	return fmt.Errorf("wfp error at %s:%d: %w", file, line, err)
}
