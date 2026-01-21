package accesslog

import (
	"net"
	"net/http"
	"slices"
	"strings"
)

// requestIP attempts to extract the source IP from a request.
// Adapted from https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html
// with the addition of some newer stdlib functions that are now
// available.
// The concept here is to look backwards through IP headers until
// the first public IP address is found. The hypothesis is that
// even if there are multiple IP addresses specified in these headers,
// the last public IP should be the hop immediately before reaching
// the server and therefore represents the "true" source IP regardless
// of the number of intermediate proxies or network hops.
func extractSourceIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// Iterate from right to left until we get a public address
		// that should be the address right before our proxy.
		for _, address := range slices.Backward(addresses) {
			// Trim the address because sometimes clients put whitespace in there.
			ip := strings.TrimSpace(address)
			// Parse the IP so that we can easily check whether it is a valid public address.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || realIP.IsPrivate() || realIP.IsLoopback() {
				continue
			}
			return ip
		}
	}
	// Fallback to the requests RemoteAddr, this is least likely to be correct but
	// should at least yield something in the event that the above has failed.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	return ip
}
