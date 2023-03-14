//go:build !android

package dns

import nbdns "github.com/netbirdio/netbird/dns"

// Server is a dns server interface
type Server interface {
	Start()
	Stop()
	UpdateDNSServer(serial uint64, update nbdns.Config) error
}
