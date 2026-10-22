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

// CachedCountryPrefixes returns fetch with each country looked up once, so routes added in one
// update fetch a country they share once, and a release func that drops the cached prefixes.
// It is not safe for concurrent use.
func CachedCountryPrefixes(fetch CountryPrefixesFunc) (CountryPrefixesFunc, func()) {
	if fetch == nil {
		return nil, func() {}
	}

	cache := make(map[string][]netip.Prefix)
	cached := func(ctx context.Context, country string) ([]netip.Prefix, error) {
		if prefixes, ok := cache[country]; ok {
			return prefixes, nil
		}
		prefixes, err := fetch(ctx, country)
		if err != nil {
			return nil, err
		}
		cache[country] = prefixes
		return prefixes, nil
	}
	return cached, func() { clear(cache) }
}

// ResolveCountries returns the prefixes of all the given countries in a new slice, so callers
// may change it without touching the fetched prefixes.
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
