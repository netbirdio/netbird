package posture

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestPeerNetworkRangeCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		check   PeerNetworkRangeCheck
		peer    nbpeer.Peer
		wantErr bool
		isValid bool
	}{
		{
			name: "Peer networks range matches the allowed range",
			check: PeerNetworkRangeCheck{
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
			name: "Peer networks range doesn't matches the allowed range",
			check: PeerNetworkRangeCheck{
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
			name: "Peer with no network range in the allow range",
			check: PeerNetworkRangeCheck{
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
			name: "Peer networks range matches the denied range",
			check: PeerNetworkRangeCheck{
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
			name: "Peer networks range doesn't matches the denied range",
			check: PeerNetworkRangeCheck{
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
			name: "Peer with no networks range in the denied range",
			check: PeerNetworkRangeCheck{
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
