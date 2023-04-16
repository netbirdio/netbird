/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package bind

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	controlFns = append(controlFns,

		// Enable receiving of the packet information (IP_PKTINFO for IPv4,
		// IPV6_PKTINFO for IPv6) that is used to implement sticky socket support.
		func(network, address string, c syscall.RawConn) error {
			var err error
			switch network {
			case "udp4":
				c.Control(func(fd uintptr) {
					err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
				})
			case "udp6":
				c.Control(func(fd uintptr) {
					err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
					if err != nil {
						return
					}
					err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
				})
			default:
				err = fmt.Errorf("unhandled network: %s: %w", network, unix.EINVAL)
			}
			return err
		},
	)
}
