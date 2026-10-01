package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	servicemanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service/manager"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestTargetAccessUpdateRevokesLegacyMapping(t *testing.T) {
	for _, broadcast := range []bool{false, true} {
		name := "cluster"
		if broadcast {
			name = "broadcast"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			server := &ProxyServiceServer{tokenStore: NewOneTimeTokenStore(ctx, testCacheStore(t))}
			server.SetProxyController(newTestProxyController())
			const cluster = "proxy.example.com"
			capable := registerFakeProxyWithCaps(server, "capable", cluster,
				&proto.ProxyCapabilities{SupportsTargetAccessControl: ptr(true)})
			legacy := registerFakeProxy(server, "legacy", cluster)
			unsupported := registerFakeProxyWithCaps(server, "unsupported", cluster,
				&proto.ProxyCapabilities{SupportsTargetAccessControl: ptr(false)})
			send := func(mapping *proto.ProxyMapping) {
				if broadcast {
					server.SendServiceUpdate(&proto.GetMappingUpdateResponse{Mapping: []*proto.ProxyMapping{mapping}})
					return
				}
				server.SendServiceUpdateToCluster(ctx, mapping, cluster)
			}
			mapping := &proto.ProxyMapping{
				Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
				Id:   "service", AccountId: "account", Domain: "app.example.com", Mode: "http",
				Path: []*proto.PathMapping{{Path: "/", Target: "http://127.0.0.1:8080"}},
			}
			send(mapping)
			for label, channel := range map[string]chan *proto.GetMappingUpdateResponse{
				"capable": capable, "legacy": legacy, "unsupported": unsupported,
			} {
				got := drainMapping(channel)
				require.NotNil(t, got, "%s must receive the initial unrestricted route", label)
				assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, got.Type,
					"all versions support inherited authentication")
			}

			for _, action := range []proto.TargetAccessAction{
				proto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK,
				proto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS,
				proto.TargetAccessAction(99),
			} {
				mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED
				mapping.Path[0].AccessAction = action
				send(mapping)
				got := drainMapping(capable)
				require.NotNil(t, got)
				assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED, got.Type,
					"a capable proxy must receive the policy to enforce or reject")
				assert.Equal(t, action, got.Path[0].AccessAction, "the selected action must survive fanout")
				for label, channel := range map[string]chan *proto.GetMappingUpdateResponse{
					"legacy": legacy, "unsupported": unsupported,
				} {
					got := drainMapping(channel)
					require.NotNil(t, got, "%s must receive a removal instead of retaining its old route", label)
					assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, got.Type,
						"an unenforceable access policy must revoke the entire mapping")
					assert.Equal(t, mapping.Id, got.Id, "removal must identify the existing mapping")
					assert.Empty(t, got.AuthToken, "a removal must not receive an authentication token")
				}
				assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED, mapping.Type,
					"filtering must not mutate the shared update")
			}

			mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED
			send(mapping)
			assert.NotNil(t, drainMapping(capable), "capable proxies must receive removals")
			assert.NotNil(t, drainMapping(legacy), "legacy proxies must receive removals")
			assert.NotNil(t, drainMapping(unsupported), "unsupported proxies must receive removals")
		})
	}
}

func TestTargetAccessFilteringPreservesSnapshotCompletion(t *testing.T) {
	mapping := &proto.ProxyMapping{
		Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:   "service", Domain: "app.example.com",
		Path: []*proto.PathMapping{{AccessAction: proto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK}},
	}
	update := &proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{mapping}, InitialSyncComplete: true,
	}
	filtered := filterMappingsForProxy(&proxyConnection{}, update)
	require.Len(t, filtered.Mapping, 1)
	assert.True(t, filtered.InitialSyncComplete, "filtering must preserve the snapshot boundary")
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, filtered.Mapping[0].Type,
		"a snapshot must revoke an unsupported cached route")
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, mapping.Type,
		"snapshot filtering must preserve the source mapping")
}

func TestTargetAccessSnapshotsRevokeUnsupportedRoutes(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	const cluster = "proxy.example.com"
	svc := &rpservice.Service{
		ID: "service", AccountID: "account", Name: "blocked", Domain: "app.example.com",
		Mode: rpservice.ModeHTTP, Enabled: true, ProxyCluster: cluster,
		Targets: []*rpservice.Target{{
			AccountID: "account", TargetType: rpservice.TargetTypeCluster,
			TargetId: "127.0.0.1", Protocol: "http", Port: 8080, Enabled: true,
			AccessAction: rpservice.TargetAccessActionBlock,
		}},
	}
	require.NoError(t, testStore.CreateService(ctx, svc))
	server := newSnapshotTestServer(t, 10)
	server.serviceManager = servicemanager.NewManager(testStore, nil, nil, nil, nil, nil)

	legacyStream := &recordingStream{}
	legacy := &proxyConnection{proxyID: "legacy", address: cluster, stream: legacyStream}
	require.NoError(t, server.sendSnapshot(ctx, legacy))
	require.Len(t, legacyStream.messages, 1)
	assert.True(t, legacyStream.messages[0].InitialSyncComplete, "legacy snapshot must finish normally")
	require.Len(t, legacyStream.messages[0].Mapping, 1)
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, legacyStream.messages[0].Mapping[0].Type,
		"legacy snapshot must clear any previously unrestricted cached mapping")
	assert.Empty(t, legacyStream.messages[0].Mapping[0].AuthToken, "removals must not allocate a token")

	syncStream := &syncRecordingStream{recvMsgs: []*proto.SyncMappingsRequest{ackMsg()}}
	require.NoError(t, server.sendSnapshotSync(ctx, legacy, syncStream))
	require.Len(t, syncStream.sent, 1)
	require.Len(t, syncStream.sent[0].Mapping, 1)
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, syncStream.sent[0].Mapping[0].Type,
		"the acknowledged snapshot must also revoke unsupported mappings")
	assert.Empty(t, syncStream.sent[0].Mapping[0].AuthToken, "acknowledged removals must not allocate a token")

	currentStream := &recordingStream{}
	current := &proxyConnection{
		proxyID: "current", address: cluster, stream: currentStream,
		capabilities: &proto.ProxyCapabilities{SupportsTargetAccessControl: ptr(true)},
	}
	require.NoError(t, server.sendSnapshot(ctx, current))
	require.Len(t, currentStream.messages, 1)
	require.Len(t, currentStream.messages[0].Mapping, 1)
	got := currentStream.messages[0].Mapping[0]
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, got.Type,
		"a capable proxy must receive the stored route")
	require.Len(t, got.Path, 1)
	assert.Equal(t, proto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK, got.Path[0].AccessAction,
		"the stored policy must reach a capable proxy in its initial snapshot")
	assert.NotEmpty(t, got.AuthToken, "a created mapping must receive its one-time token")
}
