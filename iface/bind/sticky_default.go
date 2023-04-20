//go:build !linux
// +build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package bind

// TODO: macOS, FreeBSD and other BSDs likely do support this feature set, but
// use alternatively named flags and need ports and require testing.

// getSrcFromControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func getSrcFromControl(control []byte, ep *StdNetEndpoint) {
}

// setSrcControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func setSrcControl(control *[]byte, ep *StdNetEndpoint) {
}

// srcControlSize returns the recommended buffer size for pooling sticky control
// data.
const srcControlSize = 0
