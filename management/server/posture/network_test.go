package posture

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestPrivateNetworkCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		check   PrivateNetworkCheck
		peer    nbpeer.Peer
		wantErr bool
		isValid bool
	}{
		{
			name: "Peer private networks matches the allowed range",
			check: PrivateNetworkCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/24"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{
							NetIP: netip.MustParsePrefix("192.168.0.123/24"),
						},
						{
							NetIP: netip.MustParsePrefix("fe80::6089:eaff:fe0c:232f/64"),
						},
					},
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Peer private networks doesn't matches the allowed range",
			check: PrivateNetworkCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/24"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{
							NetIP: netip.MustParsePrefix("198.19.249.3/24"),
						},
					},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Peer with no privates network in the allow range",
			check: PrivateNetworkCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/16"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			peer:    nbpeer.Peer{},
			wantErr: true,
			isValid: false,
		},
		{
			name: "Peer private networks matches the denied range",
			check: PrivateNetworkCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/24"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{
							NetIP: netip.MustParsePrefix("192.168.0.123/24"),
						},
						{
							NetIP: netip.MustParsePrefix("fe80::6089:eaff:fe0c:232f/64"),
						},
					},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Peer private networks doesn't matches the denied range",
			check: PrivateNetworkCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/24"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{
							NetIP: netip.MustParsePrefix("198.19.249.3/24"),
						},
					},
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Peer with no private networks in the denied range",
			check: PrivateNetworkCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/16"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			peer:    nbpeer.Peer{},
			wantErr: true,
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid, err := tt.check.Check(tt.peer)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}
