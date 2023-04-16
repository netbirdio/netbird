//go:build !windows && !linux && !js

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package bind

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	controlFns = append(controlFns,
		func(network, address string, c syscall.RawConn) error {
			var err error
			if network == "udp6" {
				c.Control(func(fd uintptr) {
					err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
				})
			}
			return err
		},
	)
}
