package refcounter

import "net/netip"

// RouteRefCounter is a Counter for Route, it doesn't take any input on Increment and doesn't use any output on Decrement
type RouteRefCounter = Counter[netip.Prefix, struct{}, struct{}]

// AllowedIPsRefCounter is a Counter for AllowedIPs, it takes a peer key on Increment and passes it back to Decrement
type AllowedIPsRefCounter = Counter[netip.Prefix, string, string]
