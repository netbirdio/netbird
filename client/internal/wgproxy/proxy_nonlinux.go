//go:build !linux || android

package wgproxy

// GetProxy instantiate new UserSpace proxy
func GetProxy(wgPort int) Proxy {
	return NewUSProxy(wgPort)
}
