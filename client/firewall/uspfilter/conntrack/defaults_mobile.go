//go:build ios || android

package conntrack

// Default per-tracker entry caps on mobile platforms. iOS network extensions
// are capped at ~50 MB; Android runs under aggressive memory pressure. These
// values keep conntrack footprint well under 5 MB worst case (TCPConnTrack
// is ~200 B plus map overhead).
const (
	DefaultMaxTCPEntries  = 4096
	DefaultMaxUDPEntries  = 2048
	DefaultMaxICMPEntries = 512
)
