//go:build windows

package daemonaddr

import (
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// probeTimeout bounds each transport probe. Both are local, so a daemon that is
// listening answers immediately and one that is not fails immediately.
const probeTimeout = 300 * time.Millisecond

// ResolveDaemonAddr keeps a client on the named pipe and never silently moves it
// off. When the pipe does not answer it checks the legacy loopback TCP address, so
// a client meeting a daemon that has not restarted since the upgrade can say what
// is wrong, but it does not connect there.
//
// Using that address automatically would be a downgrade the user never asked for:
// any local process can bind 127.0.0.1 while the daemon is not listening, and the
// transport carries no caller identity, so a client that accepted whatever answered
// would hand a setup key, a pre-shared key or an SSO prompt to a local impostor. An
// operator who needs the legacy address during the upgrade window can still pass
// --daemon-addr explicitly, which is a deliberate choice and still refuses the
// privileged operations.
//
// Only the pipe address is resolved. A custom address is left alone, though passing
// --daemon-addr npipe://netbird explicitly is indistinguishable from the default
// here, so it is treated the same way.
func ResolveDaemonAddr(addr string) string {
	inst := instance.Current()
	if addr != inst.DaemonAddr() {
		return addr
	}

	for _, path := range PipePaths(pipeName(addr)) {
		if pipeAvailable(path) {
			return addr
		}
	}

	legacy := inst.LegacyTCPDaemonAddr()
	if legacy == "" {
		return addr
	}
	if tcpAvailable(legacy) {
		log.Warnf("the daemon is not serving %s, but something is listening on the legacy %s. "+
			"Restart the NetBird service so it serves the pipe. That address is not used automatically: "+
			"any local user can bind it and it carries no caller identity, so pass --daemon-addr %s "+
			"explicitly if you accept that",
			addr, legacy, legacy)
	}

	return addr
}

func pipeAvailable(path string) bool {
	timeout := probeTimeout
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return false
	}
	if err := conn.Close(); err != nil {
		log.Debugf("close daemon pipe probe: %v", err)
	}
	return true
}

func tcpAvailable(addr string) bool {
	host := addr
	if _, after, ok := strings.Cut(addr, "://"); ok {
		host = after
	}

	conn, err := net.DialTimeout("tcp", host, probeTimeout)
	if err != nil {
		return false
	}
	if err := conn.Close(); err != nil {
		log.Debugf("close daemon TCP probe: %v", err)
	}
	return true
}

// pipeName returns the npipe address name of a daemon address, such as
// "netbird" for "npipe://netbird".
func pipeName(addr string) string {
	return strings.TrimPrefix(addr, pipeScheme)
}
