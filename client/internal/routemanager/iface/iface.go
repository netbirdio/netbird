//go:build !windows

package iface

// WGIface defines subset methods of interface required for router
type WGIface interface {
	wgIfaceBase
}
