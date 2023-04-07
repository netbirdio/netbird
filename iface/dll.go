//go:build windows

/*
 * Partially copied from https://github.com/WireGuard/wireguard-windows/blob/dcc0eb72a04ba2c0c83d29bd621a7f66acce0a23/driver/dll_fromrsrc_windows.go
 * With the following license:
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package iface

import (
	"fmt"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

type lazyDLL struct {
	Name   string
	Base   windows.Handle
	mu     sync.Mutex
	module *memmod.Module
	onLoad func(d *lazyDLL)
}

func (d *lazyDLL) Load() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.module))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module != nil {
		return nil
	}

	const ourModule windows.Handle = 0
	resInfo, err := windows.FindResource(ourModule, d.Name, windows.RT_RCDATA)
	if err != nil {
		return fmt.Errorf("Unable to find \"%v\" RCDATA resource: %w", d.Name, err)
	}
	data, err := windows.LoadResourceData(ourModule, resInfo)
	if err != nil {
		return fmt.Errorf("Unable to load resource: %w", err)
	}
	module, err := memmod.LoadLibrary(data)
	if err != nil {
		return fmt.Errorf("Unable to load library: %w", err)
	}
	d.Base = windows.Handle(module.BaseAddr())

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.module)), unsafe.Pointer(module))
	if d.onLoad != nil {
		d.onLoad(d)
	}
	return nil
}
func newLazyDLL(name string, onLoad func(d *lazyDLL)) *lazyDLL {
	return &lazyDLL{Name: name, onLoad: onLoad}
}
