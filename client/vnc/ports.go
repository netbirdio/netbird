// Package vnc holds shared constants for the NetBird embedded VNC stack
// so non-server consumers (CLI capture, debug tooling) can refer to the
// well-known ports without depending on internal engine packages.
package vnc

// External and internal listen ports for the embedded VNC server.
// ExternalPort is what dashboard / browser clients see; the daemon
// DNATs it to InternalPort, where the in-process VNC server actually
// listens. Both flow over the WireGuard interface. AgentLegacyPort is
// the TCP port the per-session agent used before it switched to Unix
// sockets; kept here so packet captures from older builds still get
// tagged, and so any future on-wire agent variant has a reserved port.
const (
	ExternalPort    uint16 = 5900
	InternalPort    uint16 = 25900
	AgentLegacyPort uint16 = 15900
)

// WellKnownPorts is the unordered set of ports a packet capture should
// treat as carrying NetBird VNC traffic.
var WellKnownPorts = [...]uint16{ExternalPort, InternalPort, AgentLegacyPort}

// IsWellKnownPort reports whether port matches any of WellKnownPorts.
func IsWellKnownPort(port uint16) bool {
	for _, p := range WellKnownPorts {
		if port == p {
			return true
		}
	}
	return false
}
