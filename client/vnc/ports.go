// Package vnc holds the listen ports of the NetBird embedded VNC stack so
// consumers can refer to them without depending on internal engine packages.
package vnc

// External and internal listen ports for the embedded VNC server.
// ExternalPort is what dashboard / browser clients see; the daemon
// DNATs it to InternalPort, where the in-process VNC server actually
// listens. Both flow over the NetBird interface.
const (
	ExternalPort uint16 = 5900
	InternalPort uint16 = 25900
)
