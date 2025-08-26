package bufsize

const (
	// WGBufferOverhead represents the additional buffer space needed beyond MTU
	// for WireGuard packet encapsulation (WG header + UDP + IP + safety margin)
	// Original hardcoded buffers were 1500, default MTU is 1280, so overhead = 220
	// TODO: Calculate this properly based on actual protocol overhead instead of using hardcoded difference
	WGBufferOverhead = 220
)
