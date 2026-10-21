// Package wgbackend is the single place in the client that names the WireGuard
// implementation. The rest of the code imports this package instead of the
// wireguard-go packages, so swapping the implementation only touches the aliases here.
package wgbackend
