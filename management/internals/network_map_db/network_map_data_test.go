package networkmapdb

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// disabled network resource shouldn't be in the resulting map
func TestBuildResourcePolicies_DisabledNetworkResource(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: false},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	assert.Empty(t, buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx))
}

// disabled policy shouldn't be in the resulting map
func TestBuildResourcePolicies_DisabledPolicy(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: false},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	assert.Empty(t, buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx))
}

// build ResourcePolicies via PolicyToDestinationResourceIdx only
func TestBuildResourcePolicies_ViaPolicyToDestinationResourceIdx(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
		{ID: "net-res-2", Enabled: true},
		{ID: "net-res-3", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
		{ID: "policy-2", Enabled: true},
		{ID: "policy-3", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
		"policy-2": {
			"net-res-2": struct{}{},
		},
		"policy-3": {
			"net-res-1": struct{}{},
			"net-res-2": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	resourceToPolicies := buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx)

	assert.Equal(t, map[string][]*nmdata.Policy{
		"net-res-1": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-2": {
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-3": {
			{ID: "policy-1", Enabled: true},
		},
	}, resourceToPolicies)
}

// build ResourcePolicies via PolicyToDestinationGroupIdx only
func TestBuildResourcePolicies_ViaPolicyToDestinationGroupIdx(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
		{ID: "net-res-2", Enabled: true},
		{ID: "net-res-3", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
		{ID: "policy-2", Enabled: true},
		{ID: "policy-3", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{
		"net-res-1": {
			"group-1": struct{}{},
			"group-2": struct{}{},
		},
		"net-res-2": {
			"group-2": struct{}{},
			"group-3": struct{}{},
		},
		"net-res-3": {
			"group-3": struct{}{},
			"group-4": struct{}{},
		},
	}
	policyToDestinationResourceIdx := map[string]map[string]any{}
	policyToDestinationGroupIdx := map[string]map[string]any{
		"policy-1": {
			"group-1": struct{}{},
			"group-2": struct{}{},
		},
		"policy-2": {
			"group-1": struct{}{},
			"group-4": struct{}{},
		},
		"policy-3": {
			"group-1": struct{}{},
			"group-3": struct{}{},
		},
	}

	resourceToPolicies := buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx)

	assert.Equal(t, map[string][]*nmdata.Policy{
		"net-res-1": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-2": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-3": {
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
	}, resourceToPolicies)
}

type fakeNmdataStore struct {
	name     string
	serial   atomic.Int64
	readErr  error
	stall    bool
	begins   atomic.Int32
	finishes atomic.Int32
}

func (f *fakeNmdataStore) BeginTx(ctx context.Context) (NetworkMapDBStoreConn, error) {
	if f.stall {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.begins.Add(1)
	return &fakeNmdataConn{store: f}, nil
}

func (f *fakeNmdataStore) Exec(context.Context, string, ...any) error { return nil }

type fakeNmdataConn struct {
	store *fakeNmdataStore
}

func (c *fakeNmdataConn) GetNetwork(context.Context, string) (nmdata.Network, error) {
	return nmdata.Network{Identifier: c.store.name, Serial: c.store.serial.Load()}, nil
}

func (c *fakeNmdataConn) GetPeers(context.Context, string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	return nil, nil, c.store.readErr
}

func (c *fakeNmdataConn) GetGroups(context.Context, string) ([]nmdata.Group, map[string]map[string]any, error) {
	return nil, nil, nil
}
func (c *fakeNmdataConn) GetDomains(context.Context, string) ([]Domain, error) { return nil, nil }
func (c *fakeNmdataConn) GetPolicies(context.Context, string) ([]nmdata.Policy, map[string]map[string]any, map[string]map[string]any, error) {
	return nil, nil, nil, nil
}
func (c *fakeNmdataConn) GetRoutes(context.Context, string) ([]nmdata.Route, error) { return nil, nil }
func (c *fakeNmdataConn) GetNameServerGroups(context.Context, string) ([]nmdata.NameServerGroup, error) {
	return nil, nil
}
func (c *fakeNmdataConn) GetNetworkResources(context.Context, string) ([]nmdata.NetworkResource, error) {
	return nil, nil
}
func (c *fakeNmdataConn) GetNetworkRouters(context.Context, string) (map[string]map[string]*nmdata.NetworkRouter, error) {
	return map[string]map[string]*nmdata.NetworkRouter{}, nil
}
func (c *fakeNmdataConn) GetAppliedZoneCandidates(context.Context, string) ([]networkmap.AppliedZoneCandidate, error) {
	return nil, nil
}
func (c *fakeNmdataConn) GetAccountSettings(context.Context, string) (nmdata.AccountSettingsInfo, error) {
	return nmdata.AccountSettingsInfo{}, nil
}
func (c *fakeNmdataConn) GetPostureChecks(context.Context, string) ([]nmdata.PostureChecks, map[string]string, error) {
	return nil, nil, nil
}
func (c *fakeNmdataConn) GetAllowedUsers(context.Context, string) (map[string]struct{}, map[string][]string, error) {
	return nil, nil, nil
}
func (c *fakeNmdataConn) GetDnsSettings(context.Context, string) (nmdata.DNSSettings, error) {
	return nmdata.DNSSettings{}, nil
}
func (c *fakeNmdataConn) GetNetworkXIDToPublicIdMap(context.Context, string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (c *fakeNmdataConn) GetPrivateServices(context.Context, string) ([]Service, error) {
	return nil, nil
}
func (c *fakeNmdataConn) GetProxyTargetedDomainResourceIDs(context.Context, string) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}

func (c *fakeNmdataConn) CommitTx(context.Context) error {
	c.store.finishes.Add(1)
	return nil
}

func (c *fakeNmdataConn) RollbackTx(context.Context) error {
	c.store.finishes.Add(1)
	return nil
}

func newReplicaTestStores(primarySerial, replicaSerial int64) (*NetworkMapDBStoreImpl, *fakeNmdataStore, *fakeNmdataStore) {
	primary := &fakeNmdataStore{name: "primary"}
	primary.serial.Store(primarySerial)
	replica := &fakeNmdataStore{name: "replica"}
	replica.serial.Store(replicaSerial)
	return &NetworkMapDBStoreImpl{Store: primary, Replica: replica, ReplicaWait: time.Second}, primary, replica
}

func TestReadNetworkMapData_ReplicaCaughtUp(t *testing.T) {
	s, primary, replica := newReplicaTestStores(5, 5)

	data, err := s.readNetworkMapData(context.Background(), "account")
	require.NoError(t, err)

	assert.Equal(t, "replica", data.Network.Identifier)
	assert.Equal(t, int32(1), replica.begins.Load())
	assert.Equal(t, primary.begins.Load(), primary.finishes.Load())
	assert.Equal(t, replica.begins.Load(), replica.finishes.Load())
}

func TestReadNetworkMapData_WaitsForReplica(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, replica := newReplicaTestStores(5, 4)

		time.AfterFunc(100*time.Millisecond, func() { replica.serial.Store(5) })

		start := time.Now()
		data, err := s.readNetworkMapData(context.Background(), "account")
		require.NoError(t, err)

		assert.Equal(t, "replica", data.Network.Identifier)
		assert.Equal(t, int64(5), data.Network.Serial)
		assert.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
		assert.Equal(t, replica.begins.Load(), replica.finishes.Load())
	})
}

func TestReadNetworkMapData_FallsBackToPrimaryWhenReplicaLags(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, primary, replica := newReplicaTestStores(5, 4)

		start := time.Now()
		data, err := s.readNetworkMapData(context.Background(), "account")
		require.NoError(t, err)

		assert.Equal(t, "primary", data.Network.Identifier)
		assert.GreaterOrEqual(t, time.Since(start), s.ReplicaWait)
		assert.Equal(t, primary.begins.Load(), primary.finishes.Load())
		assert.Equal(t, replica.begins.Load(), replica.finishes.Load())
	})
}

func TestReadNetworkMapData_FallsBackToPrimaryOnReplicaReadError(t *testing.T) {
	s, primary, replica := newReplicaTestStores(5, 5)
	replica.readErr = errors.New("canceling statement due to conflict with recovery")

	data, err := s.readNetworkMapData(context.Background(), "account")
	require.NoError(t, err)

	assert.Equal(t, "primary", data.Network.Identifier)
	assert.Equal(t, primary.begins.Load(), primary.finishes.Load())
	assert.Equal(t, replica.begins.Load(), replica.finishes.Load())
}

func TestReadNetworkMapData_WithoutReplicaReadsPrimaryOnce(t *testing.T) {
	primary := &fakeNmdataStore{name: "primary"}
	s := &NetworkMapDBStoreImpl{Store: primary}

	data, err := s.readNetworkMapData(context.Background(), "account")
	require.NoError(t, err)

	assert.Equal(t, "primary", data.Network.Identifier)
	assert.Equal(t, int32(1), primary.begins.Load())
	assert.Equal(t, int32(1), primary.finishes.Load())
}

func TestReadNetworkMapData_CancelledWhileWaitingForReplica(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, primary, replica := newReplicaTestStores(5, 4)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := s.readNetworkMapData(ctx, "account")
		require.ErrorIs(t, err, context.DeadlineExceeded)

		assert.Equal(t, int32(1), primary.begins.Load(), "primary should only be read for the serial")
		assert.Equal(t, primary.begins.Load(), primary.finishes.Load())
		assert.Equal(t, replica.begins.Load(), replica.finishes.Load())
	})
}

func TestReadNetworkMapData_FallsBackToPrimaryWhenReplicaStalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		metrics, err := NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), nil)
		require.NoError(t, err)

		s, primary, replica := newReplicaTestStores(5, 5)
		s.Metrics = metrics
		replica.stall = true

		start := time.Now()
		data, err := s.readNetworkMapData(context.Background(), "account")
		require.NoError(t, err)

		assert.Equal(t, "primary", data.Network.Identifier)
		assert.Equal(t, s.ReplicaWait, time.Since(start), "a stalled replica must be abandoned at the wait deadline")
		assert.Equal(t, primary.begins.Load(), primary.finishes.Load())

		reads, waits := collectReadMetrics(t, reader)
		assert.Equal(t, map[[2]string]int64{{readSourcePrimary, readReasonLagTimeout}: 1}, reads)
		assert.Equal(t, uint64(1), waits)
	})
}

func TestReadNetworkMapData_CountsReadsBySourceAndReason(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		metrics, err := NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), nil)
		require.NoError(t, err)

		s, _, replica := newReplicaTestStores(5, 5)
		s.Metrics = metrics

		_, err = s.readNetworkMapData(context.Background(), "account")
		require.NoError(t, err)

		replica.serial.Store(4)
		_, err = s.readNetworkMapData(context.Background(), "account")
		require.NoError(t, err)

		replica.serial.Store(5)
		replica.readErr = errors.New("canceling statement due to conflict with recovery")
		_, err = s.readNetworkMapData(context.Background(), "account")
		require.NoError(t, err)

		s.Replica = nil
		_, err = s.readNetworkMapData(context.Background(), "account")
		require.NoError(t, err)

		reads, waits := collectReadMetrics(t, reader)

		assert.Equal(t, map[[2]string]int64{
			{readSourceReplica, readReasonCaughtUp}:     1,
			{readSourcePrimary, readReasonLagTimeout}:   1,
			{readSourcePrimary, readReasonReplicaError}: 1,
			{readSourcePrimary, readReasonNoReplica}:    1,
		}, reads)
		assert.Equal(t, uint64(3), waits, "every replica attempt that reached the serial check records its wait")
	})
}

// collectReadMetrics returns the read counts keyed by source and reason and the
// number of recorded replica waits.
func collectReadMetrics(t *testing.T, reader *sdkmetric.ManualReader) (map[[2]string]int64, uint64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	reads := map[[2]string]int64{}
	var waits uint64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					source, _ := dp.Attributes.Value(attribute.Key("source"))
					reason, _ := dp.Attributes.Value(attribute.Key("reason"))
					reads[[2]string{source.AsString(), reason.AsString()}] = dp.Value
				}
			case metricdata.Histogram[int64]:
				for _, dp := range data.DataPoints {
					waits += dp.Count
				}
			}
		}
	}
	return reads, waits
}
