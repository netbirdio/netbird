//go:build js

package dns

import (
	"net/netip"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"
)

// tcpDNSServer is a no-op stub for the js/wasm build. The real on-demand TCP DNS
// server ([tcpstack.go]) is backed by the gvisor netstack, which is not compiled
// for the browser client (it uses the lneto netstack + websocket transport).
type tcpDNSServer struct{}

func newTCPDNSServer(mux *dns.ServeMux, tunDev tun.Device, ip netip.Addr, port uint16, mtu uint16) *tcpDNSServer {
	return &tcpDNSServer{}
}

func (t *tcpDNSServer) InjectPacket(payload []byte) {}
func (t *tcpDNSServer) Stop()                       {}
