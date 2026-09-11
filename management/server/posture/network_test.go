package posture

import (
	"context"
	"net"
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
		{
			name: "Peer connection IP matches the denied /32",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("109.41.115.194/32"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{NetIP: netip.MustParsePrefix("192.168.0.123/24")},
					},
				},
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("109.41.115.194")},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Peer connection IP does not match the denied /32",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("109.41.115.194/32"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{NetIP: netip.MustParsePrefix("192.168.0.123/24")},
					},
				},
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("8.8.8.8")},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Peer connection IP matches the allowed /32 with no NetworkAddresses",
			check: PeerNetworkRangeCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("109.41.115.194/32"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("109.41.115.194")},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "IPv6 connection IP matches the denied /128",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("2001:db8::1/128"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("2001:db8::1")},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "IPv6 connection IP does not match the denied /128",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("2001:db8::1/128"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("2001:db8::2")},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "IPv4-mapped IPv6 connection IP matches IPv4 /32",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("109.41.115.194/32"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("::ffff:109.41.115.194")},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Connection IP falls inside an allowed /24 range",
			check: PeerNetworkRangeCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("1.0.0.0/24"),
					netip.MustParsePrefix("2.2.2.2/32"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("1.0.0.55")},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Connection IP falls inside an allowed /23 range",
			check: PeerNetworkRangeCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("3.0.0.0/23"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("3.0.1.200")},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Connection IP outside the allowed /24 range",
			check: PeerNetworkRangeCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("1.0.0.0/24"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("1.0.1.5")},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Connection IP inside a denied /24 range",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("1.0.0.0/24"),
				},
			},
			peer: nbpeer.Peer{
				Location: nbpeer.Location{ConnectionIP: net.ParseIP("1.0.0.7")},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Local NIC /24 does not match a /32 rule even if host bit lines up",
			check: PeerNetworkRangeCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.5/32"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{NetIP: netip.MustParsePrefix("192.168.0.5/24")},
					},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Local NIC address inside an allowed /16 range",
			check: PeerNetworkRangeCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/16"),
				},
			},
			peer: nbpeer.Peer{
				Meta: nbpeer.PeerSystemMeta{
					NetworkAddresses: []nbpeer.NetworkAddress{
						{NetIP: netip.MustParsePrefix("192.168.5.7/24")},
					},
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Empty NetworkAddresses and empty ConnectionIP still errors",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("109.41.115.194/32"),
				},
			},
			peer:    nbpeer.Peer{},
			wantErr: true,
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid, err := tt.check.Check(context.Background(), tt.peer)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}

func TestNetworkCheck_Validate(t *testing.T) {
	testCases := []struct {
		name          string
		check         PeerNetworkRangeCheck
		expectedError bool
	}{
		{
			name: "Valid network range",
			check: PeerNetworkRangeCheck{
				Action: CheckActionAllow,
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			expectedError: false,
		},
		{
			name: "Invalid empty network range",
			check: PeerNetworkRangeCheck{
				Action: CheckActionDeny,
				Ranges: []netip.Prefix{},
			},
			expectedError: true,
		},
		{
			name: "Invalid check action",
			check: PeerNetworkRangeCheck{
				Action: "unknownAction",
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
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
