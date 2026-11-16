package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/types"
)

// A peer that the background validator approves must get its own map and appear in the
// maps of the peers a policy connects it to, without waiting for a login or sync.
func TestOnPeerValidationChanged_UpdatesChangedPeerAndItsPeers(t *testing.T) {
	_, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	err := s.CreatePolicy(ctx, &types.Policy{
		ID:        "policy-validation-change",
		AccountID: accountID,
		Enabled:   true,
		Rules: []*types.PolicyRule{{
			ID:            "rule-validation-change",
			PolicyID:      "policy-validation-change",
			Enabled:       true,
			Sources:       []string{groupIDs[0]},
			Destinations:  []string{groupIDs[1]},
			Bidirectional: true,
			Action:        types.PolicyTrafficActionAccept,
		}},
	})
	require.NoError(t, err)

	var changed, affected []string
	controller := network_map.NewMockController(gomock.NewController(t))
	controller.EXPECT().OnPeersUpdated(gomock.Any(), accountID, gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, peerIDs, affectedPeerIDs []string) error {
			changed, affected = peerIDs, affectedPeerIDs
			return nil
		})
	// A separate manager over the same store: the setup's manager still has peer update
	// goroutines in flight that read its controller.
	manager := &DefaultAccountManager{Store: s, networkMapController: controller}

	manager.onPeerValidationChanged(ctx, accountID, []string{peerIDs[0]})

	assert.Equal(t, []string{peerIDs[0]}, changed, "changed peers should be passed through")
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, affected, "the changed peer and its policy peer should be updated")
}

func TestOnPeerValidationChanged_NoPeersNoUpdate(t *testing.T) {
	// Any call on the mock fails the test.
	manager := &DefaultAccountManager{networkMapController: network_map.NewMockController(gomock.NewController(t))}

	manager.onPeerValidationChanged(context.Background(), "account", nil)
}
