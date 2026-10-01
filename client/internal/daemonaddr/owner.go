package daemonaddr

// DaemonRunsAsSelf reports whether the daemon listening at addr runs as this very
// user. That is what makes an unprivileged daemon authorize this process for the
// changes it otherwise restricts to root or an administrator, so a client can tell
// up front whether those controls are usable instead of letting a save fail.
//
// It is answered from the ownership of the socket or pipe the daemon created, so it
// costs no round trip and needs no cooperation from the daemon. Ownership that
// cannot be read is reported as false, including for a TCP address, so a caller
// reading this as "the daemon would allow it" fails closed. The daemon remains the
// only thing that authorizes anything: this only decides what a client offers.
func DaemonRunsAsSelf(addr string) bool {
	return daemonRunsAsSelf(addr)
}
