//go:build linux && !android

package wgproxy

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
	udpProxy "github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

const (
	envDisableEBPFWGProxy = "NB_DISABLE_EBPF_WG_PROXY"
)

type KernelFactory struct {
	wgPort int
	mtu    uint16

	ebpfProxy *ebpf.WGEBPFProxy
}

func NewKernelFactory(wgPort int, mtu uint16) *KernelFactory {
	f := &KernelFactory{
		wgPort: wgPort,
		mtu:    mtu,
	}

	if isEBPFDisabled() {
		log.Infof("WireGuard Proxy Factory will produce UDP proxy")
		log.Infof("eBPF WireGuard proxy is disabled via %s environment variable", envDisableEBPFWGProxy)
		return f
	}

	ebpfProxy := ebpf.NewWGEBPFProxy(wgPort, mtu)
	if err := ebpfProxy.Listen(); err != nil {
		log.Infof("WireGuard Proxy Factory will produce UDP proxy")
		log.Warnf("failed to initialize ebpf proxy, fallback to user space proxy: %s", err)
		return f
	}
	log.Infof("WireGuard Proxy Factory will produce eBPF proxy")
	f.ebpfProxy = ebpfProxy
	return f
}

func (w *KernelFactory) GetProxy() Proxy {
	if w.ebpfProxy == nil {
		return udpProxy.NewWGUDPProxy(w.wgPort, w.mtu)
	}

	return ebpf.NewProxyWrapper(w.ebpfProxy)
}

// GetProxyPort returns the eBPF proxy port, or 0 if eBPF is not active.
func (w *KernelFactory) GetProxyPort() uint16 {
	if w.ebpfProxy == nil {
		return 0
	}
	return w.ebpfProxy.GetProxyPort()
}

func (w *KernelFactory) Free() error {
	if w.ebpfProxy == nil {
		return nil
	}
	return w.ebpfProxy.Free()
}

func isEBPFDisabled() bool {
	val := os.Getenv(envDisableEBPFWGProxy)
	if val == "" {
		return false
	}
	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", envDisableEBPFWGProxy, err)
		return false
	}
	return disabled
}
