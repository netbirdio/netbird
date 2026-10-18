package android

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// hostResolver resolves the hostnames the engine itself dials (management,
// signal, relay, STUN/TURN) against the underlying network's DNS servers over
// sockets protected from the VPN.
//
// Android routes an app's ordinary lookups through the VPN network's DNS
// configuration once the tunnel is up, and the VPN app is no exception. With
// Private DNS in strict mode the OS turns every one of those lookups into
// DNS-over-TLS to the configured host, sent through the tunnel. The moment the
// tunnel loses its peers (a WiFi to cellular switch, a roaming blip) that
// deadlocks: the engine cannot resolve its own servers, so it cannot redial
// signal and relay, so the tunnel never comes back; only a manual toggle,
// which tears the VPN network down, restores DNS. Observed on a Pixel 10,
// android-client#276. Resolving over the host's own DNS servers, the way the
// tunnel resolver's upstream already does, breaks the loop.
type hostResolver struct {
	mu      sync.RWMutex
	servers []netip.AddrPort
}

// fallbackDNS is used when the platform reported no usable DNS server.
var fallbackDNS = []netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:53"),
	netip.MustParseAddrPort("8.8.8.8:53"),
}

var errNoDNSServers = errors.New("no host DNS servers")

func newHostResolver() *hostResolver {
	return &hostResolver{}
}

// install makes the engine's net.DefaultResolver use this resolver. The Go
// resolver is forced (PreferGo) so lookups never reach the platform's
// getaddrinfo, and its nameserver list is ignored in favor of dial.
func (r *hostResolver) install() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     r.dial,
	}
}

// set replaces the DNS servers used for the engine's own lookups.
func (r *hostResolver) set(list []netip.AddrPort) {
	servers := make([]netip.AddrPort, 0, len(list))
	for _, s := range list {
		if s.Addr().IsValid() && s.Port() != 0 {
			servers = append(servers, s)
		}
	}
	r.mu.Lock()
	r.servers = servers
	r.mu.Unlock()
	log.Infof("engine resolver: host DNS servers %v", servers)
}

func (r *hostResolver) current() []netip.AddrPort {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.servers) == 0 {
		return fallbackDNS
	}
	return r.servers
}

// dial is the net.Resolver Dial hook. The address the Go resolver passes is
// whatever its (absent on Android) resolv.conf yielded and is ignored; the
// first host DNS server that accepts a protected socket is used instead.
func (r *hostResolver) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	servers := r.current()
	if len(servers) == 0 {
		return nil, errNoDNSServers
	}

	var errs error
	for _, server := range servers {
		conn, err := nbnet.NewDialer().DialContext(ctx, network, server.String())
		if err == nil {
			return conn, nil
		}
		errs = errors.Join(errs, fmt.Errorf("%s: %w", server, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("dial host DNS: %w", errs)
}
