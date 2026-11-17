//go:build !windows && !darwin

package elevate

// adminWriteGIDs are the groups whose write access to an executable does not
// widen who could authorize elevating it. Only root's own group qualifies here:
// a distribution installs into root-owned directories, and there is no
// system-wide administrators group that both writes them and answers polkit.
var adminWriteGIDs = []uint32{0}
