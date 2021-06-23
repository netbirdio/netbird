// +build !linux

package iface

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func Create(iface string, address string) error {
	return CreateInUserspace(iface, address)
}
