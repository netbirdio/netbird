package controller

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/mock/gomock"
)

func TestComputeForwarderPort(t *testing.T) {
	// Test with empty peers list
	peers := []*nbpeer.Peer{}
	result := computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for empty peers list, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have old versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.26.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with old versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have new versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.DnsForwarderPort) {
		t.Errorf("Expected %d for peers with new versions, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have mixed versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with mixed versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have empty version
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with empty version, got %d", network_map.OldForwarderPort, result)
	}

	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "development",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result == int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with dev version, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have unknown version string
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "unknown",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with unknown version, got %d", network_map.OldForwarderPort, result)
	}
}

func TestGetValidatedPeerWithComponents_DeletedPeer(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockrequestBuffer := account.NewMockRequestBuffer(ctrl)

	c := Controller{
		requestBuffer: mockrequestBuffer,
	}

	mockrequestBuffer.EXPECT().GetAccountWithBackpressure(gomock.Any(), gomock.Any()).Return(&types.Account{}, nil)
	peer, components, posturechecks, dnsforwardPort, err := c.GetValidatedPeerWithComponents(context.TODO(), false, "test-account-id", &nbpeer.Peer{ID: "test-peer-id"})

	assert.Nil(t, peer)
	assert.Nil(t, components)
	assert.Nil(t, posturechecks)
	assert.Equal(t, int64(0), dnsforwardPort)
	assert.NotNil(t, err)
}

func TestUpdateAffectedPeers_CountsReason(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	metrics, err := telemetry.NewAccountManagerMetrics(ctx, sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	require.NoError(t, err)

	c := Controller{accountManagerMetrics: metrics, peersUpdateManager: update_channel.NewPeersUpdateManager(nil)}
	reason := types.UpdateReason{Resource: types.UpdateResourceZoneRecord, Operation: types.UpdateOperationCreate}

	require.NoError(t, c.UpdateAffectedPeers(ctx, "account-1", []string{"peer-1"}, reason))
	require.NoError(t, c.UpdateAffectedPeers(ctx, "account-1", nil, reason))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))

	counts := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "management.account.update.account.peers.counter" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				resource, _ := dp.Attributes.Value("resource")
				operation, _ := dp.Attributes.Value("operation")
				counts[resource.AsString()+"/"+operation.AsString()] += dp.Value
			}
		}
	}
	assert.Equal(t, map[string]int64{"zone_record/create": 1}, counts)
}
