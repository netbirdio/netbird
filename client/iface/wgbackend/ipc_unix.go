//go:build linux || darwin || freebsd || openbsd

package wgbackend

import "github.com/netbirdio/wireguard-go/ipc"

var (
	UAPIListen = ipc.UAPIListen
	UAPIOpen   = ipc.UAPIOpen
)
