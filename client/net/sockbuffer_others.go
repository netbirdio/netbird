//go:build !linux

package net

// growSocketBuffers does nothing: only the Linux kernel-mode WireGuard proxies own a UDP
// socket on the relayed data path.
func growSocketBuffers(_ any, _ int) {}
