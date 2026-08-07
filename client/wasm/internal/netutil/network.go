// Package netutil holds small networking helpers shared across the wasm
// client's proxy paths (SSH, VNC, ping).
package netutil

// TCPNetwork maps an IP-version selector to the net package's TCP network
// string: 4 -> "tcp4", 6 -> "tcp6", anything else (0/automatic) -> "tcp".
func TCPNetwork(ipVersion int) string {
	switch ipVersion {
	case 4:
		return "tcp4"
	case 6:
		return "tcp6"
	default:
		return "tcp"
	}
}
