package common

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/fakeip"
	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

// CountryPrefixesFunc fetches the prefixes the management geolocation database assigns to a country.
type CountryPrefixesFunc func(ctx context.Context, country string) ([]netip.Prefix, error)

type HandlerParams struct {
	Route                *route.Route
	RouteRefCounter      *refcounter.RouteRefCounter
	AllowedIPsRefCounter *refcounter.AllowedIPsRefCounter
	DnsRouterInterval    time.Duration
	StatusRecorder       *peer.Status
	WgInterface          iface.WGIface
	DnsServer            dns.Server
	PeerStore            *peerstore.Store
	UseNewDNSRoute       bool
	Firewall             manager.Manager
	FakeIPManager        *fakeip.Manager
	ForwarderPort        *atomic.Uint32
	CountryPrefixes      CountryPrefixesFunc
}

// ResolveCountries returns the prefixes of all the given countries.
func ResolveCountries(ctx context.Context, fetch CountryPrefixesFunc, countries []string) ([]netip.Prefix, error) {
	if fetch == nil {
		return nil, errors.New("country prefixes are not available")
	}

	var prefixes []netip.Prefix
	for _, country := range countries {
		countryPrefixes, err := fetch(ctx, country)
		if err != nil {
			return nil, fmt.Errorf("get prefixes of country %s: %w", country, err)
		}
		prefixes = append(prefixes, countryPrefixes...)
	}
	return prefixes, nil
}
