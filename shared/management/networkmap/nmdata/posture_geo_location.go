package nmdata

import "fmt"

// GeoLocation is the slim twin of posture.Location.
type GeoLocation struct {
	CountryCode string
	CityName    string
}

// GeoLocationCheck is the slim twin of posture.GeoLocationCheck.
type GeoLocationCheck struct {
	Locations []GeoLocation
	Action    string
}

func (g *GeoLocationCheck) check(peer *Peer) (bool, error) {
	if peer.Location.CountryCode == "" && peer.Location.CityName == "" {
		return false, fmt.Errorf("peer's location is not set")
	}

	for _, loc := range g.Locations {
		if loc.CountryCode == peer.Location.CountryCode {
			if loc.CityName == "" || loc.CityName == peer.Location.CityName {
				switch g.Action {
				case checkActionDeny:
					return false, nil
				case checkActionAllow:
					return true, nil
				default:
					return false, fmt.Errorf("invalid geo location action: %s", g.Action)
				}
			}
		}
	}

	if g.Action == checkActionDeny {
		return true, nil
	}
	if g.Action == checkActionAllow {
		return false, nil
	}

	return false, fmt.Errorf("invalid geo location action: %s", g.Action)
}
