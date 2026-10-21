//go:build linux || darwin || freebsd

package wgbackend

import "github.com/netbirdio/wireguard-go/tun"

var (
	CreateTUN         = tun.CreateTUN
	CreateTUNFromFile = tun.CreateTUNFromFile
)
