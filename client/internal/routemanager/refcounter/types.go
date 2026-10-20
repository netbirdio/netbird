package refcounter

import "net/netip"

// RouteRefCounter is a Counter for Route, it doesn't take any input on Increment and doesn't use any output on Decrement
type RouteRefCounter = Counter[netip.Prefix, struct{}, struct{}]

// AllowedIPsRefCounter tracks WireGuard AllowedIPs per prefix. Unlike the generic Counter it is peer-aware:
// a prefix can be claimed by several peers at once and WireGuard allows a given prefix on exactly one peer,
// so the counter records the per-peer reference count and swaps the installed peer when the active one is released.
// See allowedips.go.
