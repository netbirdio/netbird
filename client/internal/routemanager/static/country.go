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

func (r *CountryRoute) String() string {
	return r.params.Route.NetString()
}

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

func (r *CountryRoute) RemoveRoute() error {
	if r.route == nil {
		return nil
	}
	return r.route.RemoveRoute()
}

func (r *CountryRoute) AddAllowedIPs(peerKey string) error {
	if r.route == nil {
		return errCountryPrefixesNotResolved
	}
	return r.route.AddAllowedIPs(peerKey)
}

func (r *CountryRoute) RemoveAllowedIPs() error {
	if r.route == nil {
		return nil
	}
	return r.route.RemoveAllowedIPs()
}
