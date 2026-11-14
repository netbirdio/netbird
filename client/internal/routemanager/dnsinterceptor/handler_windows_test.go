//go:build windows

package dnsinterceptor

// GetInterfaceGUIDString completes iface.WGIface on Windows, which requires the
// interface GUID for DNS registration.
func (fakeWGIface) GetInterfaceGUIDString() (string, error) { return "", nil }
