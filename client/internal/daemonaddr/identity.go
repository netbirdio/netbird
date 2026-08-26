package daemonaddr

import "strings"

// CarriesIdentity reports whether the control channel at addr conveys the
// connecting process's identity to the daemon. A Unix socket carries peer
// credentials and a named pipe carries the client's token. Nothing else does, TCP
// included, and there the daemon can authorize a privileged operation for nobody
// at all: see ResolveDaemonAddr, which says as much to anyone still reaching the
// Windows daemon on the address it served before it had a pipe.
//
// A client uses this to tell whether becoming privileged would get it anywhere.
// It answers from the scheme and nothing else, so an address it does not
// recognise counts as carrying no identity.
func CarriesIdentity(addr string) bool {
	return strings.HasPrefix(addr, "unix://") || strings.HasPrefix(addr, pipeScheme)
}
