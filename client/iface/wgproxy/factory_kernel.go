//go:build linux && !android

package wgproxy

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgproxy/loopback"
	udpProxy "github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

const (
	envDisableKernelWGProxy = "NB_DISABLE_KERNEL_WG_PROXY"
	// envDisableEBPFWGProxy is a deprecated alias for envDisableKernelWGProxy.
	envDisableEBPFWGProxy = "NB_DISABLE_EBPF_WG_PROXY"
)

type KernelFactory struct {
	wgPort int
	mtu    uint16

	loopbackProxy *loopback.Proxy
}

func NewKernelFactory(wgPort int, mtu uint16) *KernelFactory {
	f := &KernelFactory{
		wgPort: wgPort,
		mtu:    mtu,
	}

	if isKernelProxyDisabled() {
		log.Infof("WireGuard Proxy Factory will produce UDP proxy")
		return f
	}

	loopbackProxy := loopback.NewProxy(wgPort, mtu)
	if err := loopbackProxy.Listen(); err != nil {
		log.Infof("WireGuard Proxy Factory will produce UDP proxy")
		log.Warnf("failed to initialize loopback proxy, fallback to user space proxy: %s", err)
		return f
	}
	log.Infof("WireGuard Proxy Factory will produce loopback proxy")
	f.loopbackProxy = loopbackProxy
	return f
}

func (w *KernelFactory) GetProxy() Proxy {
	if w.loopbackProxy == nil {
		return udpProxy.NewWGUDPProxy(w.wgPort, w.mtu)
	}

	return loopback.NewProxyWrapper(w.loopbackProxy)
}

// GetProxyPort returns the loopback proxy port, or 0 if the kernel proxy is not active.
func (w *KernelFactory) GetProxyPort() uint16 {
	if w.loopbackProxy == nil {
		return 0
	}
	return w.loopbackProxy.GetProxyPort()
}

func (w *KernelFactory) Free() error {
	if w.loopbackProxy == nil {
		return nil
	}
	return w.loopbackProxy.Free()
}

func isKernelProxyDisabled() bool {
	env := envDisableKernelWGProxy
	val := os.Getenv(env)
	if val == "" {
		env = envDisableEBPFWGProxy
		val = os.Getenv(env)
	}
	if val == "" {
		return false
	}

	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", env, err)
		return false
	}

	if disabled {
		log.Infof("kernel WireGuard proxy is disabled via %s", env)
	}
	return disabled
}
