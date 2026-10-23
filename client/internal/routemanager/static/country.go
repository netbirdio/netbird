package static

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/netbirdio/netbird/client/internal/routemanager/common"
)

var errCountryPrefixesNotResolved = errors.New("country prefixes are not resolved")

// CountryRoute routes the prefixes of the countries of a country route. Management sends only
// the country codes, so the prefixes are fetched when the route is added.
type CountryRoute struct {
	params common.HandlerParams
	route  *Route
}

// NewCountryRoute returns a handler for a country route.
func NewCountryRoute(params common.HandlerParams) *CountryRoute {
	return &CountryRoute{params: params}
}

// String returns the route's countries.
func (r *CountryRoute) String() string {
	return r.params.Route.NetString()
}

// AddRoute fetches the prefixes of the route's countries and installs an OS route for each,
// leaving out IPv6 prefixes when the interface has no IPv6.
func (r *CountryRoute) AddRoute(ctx context.Context) error {
	prefixes, err := common.ResolveCountries(ctx, r.params.CountryPrefixes, r.params.Route.Countries)
	if err != nil {
		return err
	}

	if r.params.WgInterface == nil || !r.params.WgInterface.Address().HasIPv6() {
		prefixes = slices.DeleteFunc(prefixes, func(p netip.Prefix) bool {
			return p.Addr().Is6()
		})
	}

	route := newRoute(r.params, prefixes)
	if err := route.AddRoute(ctx); err != nil {
		return err
	}
	r.route = route
	return nil
}

// RemoveRoute removes the OS routes AddRoute installed.
func (r *CountryRoute) RemoveRoute() error {
	if r.route == nil {
		return nil
	}
	return r.route.RemoveRoute()
}

// AddAllowedIPs routes the fetched prefixes to the given peer. It fails until AddRoute has
// fetched them.
func (r *CountryRoute) AddAllowedIPs(peerKey string) error {
	if r.route == nil {
		return errCountryPrefixesNotResolved
	}
	return r.route.AddAllowedIPs(peerKey)
}

// RemoveAllowedIPs removes the prefixes from the peer AddAllowedIPs routed them to.
func (r *CountryRoute) RemoveAllowedIPs() error {
	if r.route == nil {
		return nil
	}
	return r.route.RemoveAllowedIPs()
}
