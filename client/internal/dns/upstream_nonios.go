//go:build !ios

package dns

import (
	"net"

	"github.com/miekg/dns"
)

// getClientPrivate returns a new DNS client bound to the local IP address of the Netbird interface
// This method is needed for iOS
func (u *upstreamResolver) getClientPrivate() *dns.Client {
	dialer := &net.Dialer{}
	client := &dns.Client{
		Dialer: dialer,
	}
	return client
}
