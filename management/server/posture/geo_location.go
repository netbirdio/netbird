package posture

import (
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
	return false, nil
}

func (g *GeoLocationCheck) Name() string {
	return GeoLocationCheckName
}
