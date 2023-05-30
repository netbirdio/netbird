//go:build !linux

package wgproxy

// GetProxy instantiate new UserSpace proxy
func GetProxy(wgPort int) Proxy {
	return NewUSProxy()
}
