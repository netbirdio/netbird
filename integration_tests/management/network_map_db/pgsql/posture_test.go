//go:build integration

package networkmap_pgsql

import (
	"context"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetPostureChecks(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into posture_checks (id, account_id, public_id, checks)
		VALUES('posturecheck-1','account-1','posturecheck-1-public',
		'{"NBVersionCheck":{"MinVersion":"0.25.0"},
		  "OSVersionCheck":{"Darwin":{"MinVersion":"12.0"}},
		  "GeoLocationCheck":{"Locations":[{"CountryCode":"FI","CityName":""}],"Action":"allow"},
		  "PeerNetworkRangeCheck":{"Action":"deny","Ranges":["192.168.0.1/24"]}}')`)

	execQuery(t, ctx,
		`insert into posture_checks (id, account_id, public_id, checks)
		VALUES('posturecheck-2','account-1','posturecheck-2-public',
		'{"NBVersionCheck":{"MinVersion":"0.25.0"},
		  "OSVersionCheck":{"Android":{"MinVersion":"0"}},
		  "GeoLocationCheck":{"Locations":[{"CountryCode":"US","CityName":"Harker Heights"}],"Action":"allow"},
		  "PeerNetworkRangeCheck":{"Action":"allow","Ranges":["0.0.0.0/0"]}}')`)
	execQuery(t, ctx,
		`insert into posture_checks (id, account_id, public_id, checks)
		VALUES('posturecheck-3','account-1','posturecheck-3-public', null)`)

	postureChecks, idToPublicIDIdx, err := conn(t, ctx).GetPostureChecks(ctx, "account-1")
	assert.NoError(t, err)
	assert.Equal(t, idToPublicIDIdx, map[string]string{
		"posturecheck-1": "posturecheck-1-public",
		"posturecheck-2": "posturecheck-2-public",
		"posturecheck-3": "posturecheck-3-public",
	})
	assert.Contains(t, postureChecks, nmdata.PostureChecks{
		ID: "posturecheck-1",
		Checks: nmdata.ChecksDefinition{
			NBVersionCheck:        &nmdata.NBVersionCheck{MinVersion: "0.25.0"},
			OSVersionCheck:        &nmdata.OSVersionCheck{Darwin: &nmdata.MinVersionCheck{MinVersion: "12.0"}},
			GeoLocationCheck:      &nmdata.GeoLocationCheck{Locations: []nmdata.GeoLocation{{CountryCode: "FI"}}, Action: "allow"},
			PeerNetworkRangeCheck: &nmdata.PeerNetworkRangeCheck{Action: "deny", Ranges: []netip.Prefix{netip.MustParsePrefix("192.168.0.1/24")}},
		}})
	assert.Contains(t, postureChecks, nmdata.PostureChecks{
		ID: "posturecheck-2",
		Checks: nmdata.ChecksDefinition{
			NBVersionCheck:        &nmdata.NBVersionCheck{MinVersion: "0.25.0"},
			OSVersionCheck:        &nmdata.OSVersionCheck{Android: &nmdata.MinVersionCheck{MinVersion: "0"}},
			GeoLocationCheck:      &nmdata.GeoLocationCheck{Locations: []nmdata.GeoLocation{{CountryCode: "US", CityName: "Harker Heights"}}, Action: "allow"},
			PeerNetworkRangeCheck: &nmdata.PeerNetworkRangeCheck{Action: "allow", Ranges: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		}})
	assert.Contains(t, postureChecks, nmdata.PostureChecks{
		ID: "posturecheck-3"})
}
