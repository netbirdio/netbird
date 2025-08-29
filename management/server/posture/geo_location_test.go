package posture

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/server/peer"

	"github.com/stretchr/testify/assert"
)

func TestGeoLocationCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		input   peer.Peer
		check   GeoLocationCheck
		wantErr bool
		isValid bool
	}{
		{
			name: "Peer location matches the location in the allow sets",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Berlin",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "US",
						CityName:    "Los Angeles",
					},
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
				Action: CheckActionAllow,
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Peer location matches the location in the allow country only",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Berlin",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "DE",
					},
				},
				Action: CheckActionAllow,
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Peer location doesn't match the location in the allow sets",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Frankfurt am Main",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
					{
						CountryCode: "US",
						CityName:    "Los Angeles",
					},
				},
				Action: CheckActionAllow,
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Peer location doesn't match the location in the allow country only",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Frankfurt am Main",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "US",
					},
				},
				Action: CheckActionAllow,
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Peer location matches the location in the deny sets",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Berlin",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
					{
						CountryCode: "US",
						CityName:    "Los Angeles",
					},
				},
				Action: CheckActionDeny,
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Peer location matches the location in the deny country only",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Berlin",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "DE",
					},
					{
						CountryCode: "US",
					},
				},
				Action: CheckActionDeny,
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Peer location doesn't match the location in the deny sets",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Frankfurt am Main",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
					{
						CountryCode: "US",
						CityName:    "Los Angeles",
					},
				},
				Action: CheckActionDeny,
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Peer location doesn't match the location in the deny country only",
			input: peer.Peer{
				Location: peer.Location{
					CountryCode: "DE",
					CityName:    "Frankfurt am Main",
				},
			},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "US",
						CityName:    "Los Angeles",
					},
				},
				Action: CheckActionDeny,
			},
			wantErr: false,
			isValid: true,
		},
		{
			name:  "Peer with no location in the allow sets",
			input: peer.Peer{},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
				Action: CheckActionAllow,
			},
			wantErr: true,
			isValid: false,
		},
		{
			name:  "Peer with no location in the deny sets",
			input: peer.Peer{},
			check: GeoLocationCheck{
				Locations: []Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
				Action: CheckActionDeny,
			},
			wantErr: true,
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid, err := tt.check.Check(context.Background(), tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}

func TestGeoLocationCheck_Validate(t *testing.T) {
	testCases := []struct {
		name          string
		check         GeoLocationCheck
		expectedError bool
	}{
		{
			name: "Valid location list",
			check: GeoLocationCheck{
				Action: CheckActionAllow,
				Locations: []Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
			},
			expectedError: false,
		},
		{
			name: "Invalid empty location list",
			check: GeoLocationCheck{
				Action:    CheckActionDeny,
				Locations: []Location{},
			},
			expectedError: true,
		},
		{
			name: "Invalid empty country name",
			check: GeoLocationCheck{
				Action: CheckActionDeny,
				Locations: []Location{
					{
						CityName: "Los Angeles",
					},
				},
			},
			expectedError: true,
		},
		{
			name: "Invalid check action",
			check: GeoLocationCheck{
				Action: "unknownAction",
				Locations: []Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
			},
			expectedError: true,
		},
		{
			name: "Invalid country code",
			check: GeoLocationCheck{
				Action: CheckActionAllow,
				Locations: []Location{
					{
						CountryCode: "USA",
					},
				},
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.check.Validate()
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
