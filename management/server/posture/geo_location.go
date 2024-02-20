package posture

import (
	"fmt"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	GeoLocationActionAllow string = "allow"
	GeoLocationActionDeny  string = "deny"
)

type Location struct {
	// CountryCode 2-letter ISO 3166-1 alpha-2 code that represents the country
	CountryCode string

	// CityName Commonly used English name of the city
	CityName string
}

var _ Check = (*GeoLocationCheck)(nil)

type GeoLocationCheck struct {
	// Locations list of geolocations, to which the policy applies
	Locations []Location

	// Action to take upon policy match
	Action string
}

func (g *GeoLocationCheck) Check(peer nbpeer.Peer) (bool, error) {
	// deny if the peer location is not evaluated
	if peer.Location.CountryCode == "" && peer.Location.CityName == "" {
		return false, fmt.Errorf("peer's location is not set")
	}

	for _, loc := range g.Locations {
		if loc.CountryCode == peer.Location.CountryCode {
			if loc.CityName == "" || loc.CityName == peer.Location.CityName {
				switch g.Action {
				case GeoLocationActionDeny:
					return false, nil
				case GeoLocationActionAllow:
					return true, nil
				default:
					return false, fmt.Errorf("invalid geo location action: %s", g.Action)
				}
			}
		}
	}
	// At this point, no location in the list matches the peer's location
	// For action deny and no location match, allow the peer
	if g.Action == GeoLocationActionDeny {
		return true, nil
	}
	// For action allow and no location match, deny the peer
	if g.Action == GeoLocationActionAllow {
		return false, nil
	}

	return false, fmt.Errorf("invalid geo location action: %s", g.Action)
}

func (g *GeoLocationCheck) Name() string {
	return GeoLocationCheckName
}
