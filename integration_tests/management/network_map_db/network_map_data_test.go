//go:build integration

package networkmap_pgsql

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/management/server/integrations/extra_settings"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/assert"
)

//go:embed network_map_data_golden.json
var goldenNMap string

const EnvUpdateGoldenData = "NMAP_UPDATE_GOLDEN_DATA"

func TestGetNetworkMapData(t *testing.T) {
	ctx := context.TODO()
	storeImpl := networkmapdb.NetworkMapDBStoreImpl{
		Store:                   store(t),
		ExtraSettingsManager:    &extraSettingsManagerForTesting{},
		IntegratedPeerValidator: &peerValidatorForTesting{},
	}

	nmap, err := storeImpl.GetNetworkMapData(ctx, "account-1")
	assert.NoError(t, err)

	serializedNMap, err := json.MarshalIndent(nmap, "", "  ")
	assert.NoError(t, err)

	if _, ok := os.LookupEnv(EnvUpdateGoldenData); ok {
		_, filename, _, _ := runtime.Caller(0)
		tosavepath := filepath.Join(filepath.Dir(filename), "network_map_data_golden.json")
		err = os.WriteFile(tosavepath, serializedNMap, 0644)
		assert.NoError(t, err)
		goldenNMap = string(serializedNMap)
	}
	assert.Equal(t, goldenNMap, string(serializedNMap))
}

// need these calls for the test
func (*extraSettingsManagerForTesting) GetExtraSettings(ctx context.Context, accountID string) (*types.ExtraSettings, error) {
	return &types.ExtraSettings{}, nil
}
func (*peerValidatorForTesting) GetValidatedPeers(ctx context.Context, accountID string, groups []*nmdata.Group, peers []*nmdata.Peer, extraSettings *types.ExtraSettings) (map[string]struct{}, error) {
	return map[string]struct{}{
		"peer-id-1": {},
		"peer-id-2": {},
		"peer-id-3": {},
	}, nil
}

type extraSettingsManagerForTesting struct{}

func (*extraSettingsManagerForTesting) GetExtraSettingsManager() extra_settings.Manager { return nil }
func (*extraSettingsManagerForTesting) GetSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error) {
	return nil, nil
}
func (*extraSettingsManagerForTesting) UpdateExtraSettings(ctx context.Context, accountID, userID string, extraSettings *types.ExtraSettings) (bool, error) {
	return false, nil
}
func (*extraSettingsManagerForTesting) GetEffectiveNetworkRanges(ctx context.Context, accountID string) (v4, v6 netip.Prefix, err error) {
	return netip.Prefix{}, netip.Prefix{}, nil
}

type peerValidatorForTesting struct{}

func (*peerValidatorForTesting) ValidateExtraSettings(ctx context.Context, newExtraSettings *types.ExtraSettings, oldExtraSettings *types.ExtraSettings, userID string, accountID string) error {
	return nil
}
func (*peerValidatorForTesting) ValidatePeer(ctx context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
	return nil, false, nil
}
func (*peerValidatorForTesting) PreparePeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings, temporary bool) *nbpeer.Peer {
	return nil
}
func (*peerValidatorForTesting) IsNotValidPeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings) (bool, bool, error) {
	return false, false, nil
}
func (*peerValidatorForTesting) GetInvalidPeers(ctx context.Context, accountID string, extraSettings *types.ExtraSettings) (map[string]string, error) {
	return nil, nil
}
func (*peerValidatorForTesting) PeerDeleted(ctx context.Context, accountID, peerID string, extraSettings *types.ExtraSettings) error {
	return nil
}
func (*peerValidatorForTesting) SetPeerInvalidationListener(fn func(accountID string, peerIDs []string)) {
}
func (*peerValidatorForTesting) Stop(ctx context.Context) {}
func (*peerValidatorForTesting) ValidateFlowResponse(ctx context.Context, peerKey string, flowResponse *proto.PKCEAuthorizationFlow) *proto.PKCEAuthorizationFlow {
	return nil
}
