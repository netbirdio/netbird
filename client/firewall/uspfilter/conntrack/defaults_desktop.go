//go:build !ios && !android

package conntrack

// Default per-tracker entry caps on desktop/server platforms. These mirror
// typical Linux netfilter nf_conntrack_max territory with ample headroom.
const (
	DefaultMaxTCPEntries  = 65536
	DefaultMaxUDPEntries  = 16384
	DefaultMaxICMPEntries = 2048
)
