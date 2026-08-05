package daemonaddr

import "strings"

// CarriesIdentity reports whether the control channel at addr conveys the
// connecting process's identity to the daemon. A Unix socket carries peer
// credentials and a named pipe carries the client's token; loopback TCP carries
// neither, so on such an address the daemon cannot authorize a privileged
// operation for anybody. A client uses this to tell whether becoming privileged
// would get it anywhere: on an identity-less address it would not, and the only
// way forward is to move the daemon onto one that carries identity.
func CarriesIdentity(addr string) bool {
	return strings.HasPrefix(addr, "unix://") || strings.HasPrefix(addr, pipeScheme)
}
