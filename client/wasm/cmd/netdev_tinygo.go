//go:build js && tinygo

package main

import (
	"github.com/netbirdio/netbird/client/wasm/internal/gonetfake"
	"github.com/soypat/lneto/x/netdev"
)

// fakeNet is the netdev every net call in the wasm build goes through. Its Dial
// is unset, so sockets reach other sockets in this program and nothing leaves
// it; wiring a transport in there is what makes this build talk to a network.
var fakeNet = &gonetfake.GoNetFake{}

// TinyGo's net package holds a single netdev that every Conn goes through, and
// it starts out as a nop whose methods all return ErrNetdevNotSet. Nothing in a
// wasm build sets it, so the first dial out of the client fails before it
// reaches the network. UseNetdev is the linkname seam net exposes for that; it
// must run before anything dials, hence init.
//
// rawsock.GoNet stood here, but its implementation is chosen by build tag and
// GOOS=js selects the baremetal file, whose every method returns
// ErrUnsupported. The fake at least makes listening and dialling work.
func init() {
	netdev.UseNetdev(fakeNet)
}
