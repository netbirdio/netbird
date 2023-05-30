//go:build linux && !android

package wgproxy

import log "github.com/sirupsen/logrus"

// GetProxy instantiate a new proxy. In case of issue with eBPF it is fallback with to general user space proxy
func GetProxy(wgPort int) Proxy {
	proxy := NewWGEBPFProxy(wgPort)
	err := proxy.Listen()
	if err == nil {
		return proxy
	}
	log.Errorf("failed to listen ebpf proxy: %s", err)
	return NewUSProxy(wgPort)
}
