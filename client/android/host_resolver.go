package android

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// hostResolver resolves the hostnames the engine itself dials (management,
// signal, relay, STUN/TURN) against the underlying network's DNS servers over
// sockets protected from the VPN.
//
// Once the tunnel is up, Android routes the VPN app's own lookups through the
// VPN network's DNS configuration like any other app's, and with Private DNS
// in strict mode it sends them as DNS-over-TLS through the tunnel. While the
// tunnel has no peers those lookups cannot complete, so the engine cannot
// resolve the servers it needs to redial. Resolving over the host's own DNS
// servers, as the tunnel resolver's upstream already does, avoids that.
type hostResolver struct {
	mu      sync.RWMutex
	servers []netip.AddrPort
	// next rotates the starting server across dial calls so the Go resolver's
	// retries reach every configured server, not only the first one.
	next uint32
	// dialContext opens the protected socket; replaced in tests.
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// fallbackDNS is used when the platform reported no usable DNS server.
var fallbackDNS = []netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:53"),
	netip.MustParseAddrPort("8.8.8.8:53"),
}

var errNoDNSServers = errors.New("no host DNS servers")

func newHostResolver() *hostResolver {
	return &hostResolver{
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nbnet.NewDialer().DialContext(ctx, network, address)
		},
	}
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
// whatever its (absent on Android) resolv.conf yielded and is ignored in favor
// of the host DNS servers. A UDP dial succeeds whether or not the server
// answers, so each call starts from the next server in the list: the Go
// resolver dials again for every retry, and the retries therefore move on to
// the other servers when one does not respond.
func (r *hostResolver) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	servers := r.current()
	if len(servers) == 0 {
		return nil, errNoDNSServers
	}

	start := int((atomic.AddUint32(&r.next, 1) - 1) % uint32(len(servers)))
	var errs error
	for i := range servers {
		server := servers[(start+i)%len(servers)]
		conn, err := r.dialContext(ctx, network, server.String())
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
