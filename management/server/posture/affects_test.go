package posture

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestAffectsPosture(t *testing.T) {
	processCheck := &Checks{Checks: ChecksDefinition{ProcessCheck: &ProcessCheck{}}}
	osCheck := &Checks{Checks: ChecksDefinition{OSVersionCheck: &OSVersionCheck{}}}
	nbCheck := &Checks{Checks: ChecksDefinition{NBVersionCheck: &NBVersionCheck{}}}
	geoCheck := &Checks{Checks: ChecksDefinition{GeoLocationCheck: &GeoLocationCheck{}}}

	privateRangeCheck := &Checks{Checks: ChecksDefinition{
		PeerNetworkRangeCheck: &PeerNetworkRangeCheck{
			Ranges: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
	}}
	publicRangeCheck := &Checks{Checks: ChecksDefinition{
		PeerNetworkRangeCheck: &PeerNetworkRangeCheck{
			Ranges: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		},
	}}
	mixedRangeCheck := &Checks{Checks: ChecksDefinition{
		PeerNetworkRangeCheck: &PeerNetworkRangeCheck{
			Ranges: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.0/24"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
		},
	}}

	tests := []struct {
		name   string
		diff   *nbpeer.MetaDiff
		checks []*Checks
		want   bool
	}{
		{
			name:   "nil diff never affects posture",
			diff:   nil,
			checks: []*Checks{processCheck},
			want:   false,
		},
		{
			name:   "process check affected by files change",
			diff:   &nbpeer.MetaDiff{Files: true},
			checks: []*Checks{processCheck},
			want:   true,
		},
		{
			name:   "process check ignores unrelated change",
			diff:   &nbpeer.MetaDiff{Hostname: true},
			checks: []*Checks{processCheck},
			want:   false,
		},
		{
			name:   "os check affected by os version change",
			diff:   &nbpeer.MetaDiff{OSVersion: true},
			checks: []*Checks{osCheck},
			want:   true,
		},
		{
			name:   "nb check affected by wt version change",
			diff:   &nbpeer.MetaDiff{WtVersion: true},
			checks: []*Checks{nbCheck},
			want:   true,
		},
		{
			name:   "geo check affected by location change",
			diff:   &nbpeer.MetaDiff{LocationChanged: true},
			checks: []*Checks{geoCheck},
			want:   true,
		},
		{
			name:   "network range check not affected without network address or location change",
			diff:   &nbpeer.MetaDiff{Hostname: true},
			checks: []*Checks{privateRangeCheck},
			want:   false,
		},
		{
			name:   "private range check affected by network address change",
			diff:   &nbpeer.MetaDiff{NetworkAddresses: true},
			checks: []*Checks{privateRangeCheck},
			want:   true,
		},
		{
			name:   "public range check not affected by network address change alone",
			diff:   &nbpeer.MetaDiff{NetworkAddresses: true},
			checks: []*Checks{publicRangeCheck},
			want:   false,
		},
		{
			name:   "public range check affected by location change alone",
			diff:   &nbpeer.MetaDiff{LocationChanged: true},
			checks: []*Checks{publicRangeCheck},
			want:   true,
		},
		{
			name:   "private range check affected by location change alone",
			diff:   &nbpeer.MetaDiff{LocationChanged: true},
			checks: []*Checks{privateRangeCheck},
			want:   true,
		},
		{
			name:   "public range check affected when location also changed",
			diff:   &nbpeer.MetaDiff{NetworkAddresses: true, LocationChanged: true},
			checks: []*Checks{publicRangeCheck},
			want:   true,
		},
		{
			name:   "mixed ranges affected by network address change due to private range",
			diff:   &nbpeer.MetaDiff{NetworkAddresses: true},
			checks: []*Checks{mixedRangeCheck},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AffectsPosture(tt.diff, tt.checks)
			assert.Equal(t, tt.want, got, "AffectsPosture result should match expectation")
		})
	}
}
