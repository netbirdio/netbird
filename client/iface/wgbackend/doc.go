// Package wgbackend is the single place in the client's hand-written code that names
// the WireGuard implementation. Other packages import it instead of the wireguard-go
// packages, so swapping the implementation only touches the aliases here and the
// generated mocks.
package wgbackend
