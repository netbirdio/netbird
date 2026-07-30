//go:build !ios

package dynamic

import (
	"context"
	"net"

	"github.com/netbirdio/netbird/shared/management/domain"
)

func (r *Route) getIPsFromResolver(ctx context.Context, domain domain.Domain) ([]net.IP, error) {
	return lookupHostIPs(ctx, domain)
}
