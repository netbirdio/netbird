//go:build js && tinygo

package main

import (
	"github.com/soypat/lneto/x/netdev"
	"github.com/soypat/lneto/x/rawsock"
)

// TinyGo's net package holds a single netdev that every Conn goes through, and
// it starts out as a nop whose methods all return ErrNetdevNotSet. Nothing in a
// wasm build sets it, so the first dial out of the client fails before it
// reaches the network. UseNetdev is the linkname seam net exposes for that; it
// must run before anything dials, hence init.
func init() {
	netdev.UseNetdev(rawsock.GoNet{})
}
