package dns

import (
	"context"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/iface"
)

// Server is a dns server interface
type Server interface {
	Start()
	Stop()
	UpdateDNSServer(serial uint64, update nbdns.Config) error
}

// DefaultServer dummy dns server
type DefaultServer struct {
}

// NewDefaultServer On Android the DNS feature is not supported yet
func NewDefaultServer(ctx context.Context, wgInterface *iface.WGIface, customAddress string) (*DefaultServer, error) {
	return &DefaultServer{}, nil
}

// Start dummy implementation
func (s DefaultServer) Start() {

}

// Stop dummy implementation
func (s DefaultServer) Stop() {

}

// UpdateDNSServer dummy implementation
func (s DefaultServer) UpdateDNSServer(serial uint64, update nbdns.Config) error {
	return nil
}
