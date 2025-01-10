package types

import "testing"

func TestNewNetworkRouter(t *testing.T) {
	tests := []struct {
		name          string
		accountID     string
		networkID     string
		peer          string
		peerGroups    []string
		masquerade    bool
		metric        int
		enabled       bool
		expectedError bool
	}{
		// Valid cases
		{
			name:          "Valid with peer only",
			networkID:     "network-1",
			accountID:     "account-1",
			peer:          "peer-1",
			peerGroups:    nil,
			masquerade:    true,
			metric:        100,
			enabled:       true,
			expectedError: false,
		},
		{
			name:          "Valid with peerGroups only",
			networkID:     "network-2",
			accountID:     "account-2",
			peer:          "",
			peerGroups:    []string{"group-1", "group-2"},
			masquerade:    false,
			metric:        200,
			enabled:       false,
			expectedError: false,
		},
		{
			name:          "Valid with no peer or peerGroups",
			networkID:     "network-3",
			accountID:     "account-3",
			peer:          "",
			peerGroups:    nil,
			masquerade:    true,
			metric:        300,
			enabled:       true,
			expectedError: false,
		},

		// Invalid cases
		{
			name:          "Invalid with both peer and peerGroups",
			networkID:     "network-4",
			accountID:     "account-4",
			peer:          "peer-2",
			peerGroups:    []string{"group-3"},
			masquerade:    false,
			metric:        400,
			enabled:       false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewNetworkRouter(tt.accountID, tt.networkID, tt.peer, tt.peerGroups, tt.masquerade, tt.metric, tt.enabled)

			if tt.expectedError && err == nil {
				t.Fatalf("Expected an error, got nil")
			}

			if tt.expectedError == false {
				if router == nil {
					t.Fatalf("Expected a NetworkRouter object, got nil")
				}

				if router.AccountID != tt.accountID {
					t.Errorf("Expected AccountID %s, got %s", tt.accountID, router.AccountID)
				}

				if router.NetworkID != tt.networkID {
					t.Errorf("Expected NetworkID %s, got %s", tt.networkID, router.NetworkID)
				}

				if router.Peer != tt.peer {
					t.Errorf("Expected Peer %s, got %s", tt.peer, router.Peer)
				}

				if len(router.PeerGroups) != len(tt.peerGroups) {
					t.Errorf("Expected PeerGroups %v, got %v", tt.peerGroups, router.PeerGroups)
				}

				if router.Masquerade != tt.masquerade {
					t.Errorf("Expected Masquerade %v, got %v", tt.masquerade, router.Masquerade)
				}

				if router.Metric != tt.metric {
					t.Errorf("Expected Metric %d, got %d", tt.metric, router.Metric)
				}

				if router.Enabled != tt.enabled {
					t.Errorf("Expected Enabled %v, got %v", tt.enabled, router.Enabled)
				}
			}
		})
	}
}
