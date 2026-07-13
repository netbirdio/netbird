package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestIntegration_SyncMappings_HappyPath(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.SyncMappings(ctx)
	require.NoError(t, err)

	// Send init.
	err = stream.Send(&proto.SyncMappingsRequest{
		Msg: &proto.SyncMappingsRequest_Init{
			Init: &proto.SyncMappingsInit{
				ProxyId: "sync-proxy-1",
				Version: "test-v1",
				Address: "test.proxy.io",
			},
		},
	})
	require.NoError(t, err)

	mappingsByID := make(map[string]*proto.ProxyMapping)
	for {
		msg, err := stream.Recv()
		require.NoError(t, err)
		for _, m := range msg.GetMapping() {
			mappingsByID[m.GetId()] = m
		}

		// Ack every batch.
		err = stream.Send(&proto.SyncMappingsRequest{
			Msg: &proto.SyncMappingsRequest_Ack{Ack: &proto.SyncMappingsAck{}},
		})
		require.NoError(t, err)

		if msg.GetInitialSyncComplete() {
			break
		}
	}

	assert.Len(t, mappingsByID, 2, "Should receive 2 mappings")

	rp1 := mappingsByID["rp-1"]
	require.NotNil(t, rp1)
	assert.Equal(t, "app1.test.proxy.io", rp1.GetDomain())
	assert.Equal(t, "test-account-1", rp1.GetAccountId())
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, rp1.GetType())
	assert.NotEmpty(t, rp1.GetAuthToken(), "Should have auth token")

	rp2 := mappingsByID["rp-2"]
	require.NotNil(t, rp2)
	assert.Equal(t, "app2.test.proxy.io", rp2.GetDomain())
}

func TestIntegration_SyncMappings_CustomTCPMappingDeliveredWithCapabilities(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	ctx := context.Background()
	tcpSvc := &service.Service{
		ID:           "tcp-custom",
		AccountID:    "test-account-1",
		Name:         "Custom TCP",
		Domain:       "ssh.test.proxy.io",
		ProxyCluster: "test.proxy.io",
		Mode:         "tcp",
		ListenPort:   10001,
		Enabled:      true,
		Targets: []*service.Target{{
			Host:       "10.0.0.5",
			Port:       22,
			Protocol:   "tcp",
			TargetId:   "peer-ssh",
			TargetType: "peer",
			Enabled:    true,
		}},
	}
	require.NoError(t, setup.store.CreateService(ctx, tcpSvc))

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)
	receiveSnapshot := func(proxyID string, caps *proto.ProxyCapabilities) map[string]*proto.ProxyMapping {
		t.Helper()

		streamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		stream, err := client.SyncMappings(streamCtx)
		require.NoError(t, err)

		err = stream.Send(&proto.SyncMappingsRequest{
			Msg: &proto.SyncMappingsRequest_Init{
				Init: &proto.SyncMappingsInit{
					ProxyId:      proxyID,
					Version:      "test-v1",
					Address:      "test.proxy.io",
					Capabilities: caps,
				},
			},
		})
		require.NoError(t, err)

		mappingsByID := make(map[string]*proto.ProxyMapping)
		for {
			msg, err := stream.Recv()
			require.NoError(t, err)
			for _, m := range msg.GetMapping() {
				mappingsByID[m.GetId()] = m
			}

			err = stream.Send(&proto.SyncMappingsRequest{
				Msg: &proto.SyncMappingsRequest_Ack{Ack: &proto.SyncMappingsAck{}},
			})
			require.NoError(t, err)

			if msg.GetInitialSyncComplete() {
				break
			}
		}
		return mappingsByID
	}

	legacyMappings := receiveSnapshot("sync-proxy-no-capabilities", nil)
	assert.NotContains(t, legacyMappings, "tcp-custom",
		"legacy proxies that do not report capabilities must not receive TCP custom-port mappings")

	supportsCustomPorts := true
	modernMappings := receiveSnapshot("sync-proxy-custom-ports", &proto.ProxyCapabilities{
		SupportsCustomPorts: &supportsCustomPorts,
	})

	tcpMapping := modernMappings["tcp-custom"]
	require.NotNil(t, tcpMapping, "capability-aware proxy must receive TCP custom-port mapping")
	assert.Equal(t, "tcp", tcpMapping.GetMode())
	assert.Equal(t, int32(10001), tcpMapping.GetListenPort())
	require.Len(t, tcpMapping.GetPath(), 1)
	assert.Equal(t, "10.0.0.5:22", tcpMapping.GetPath()[0].GetTarget())
	assert.NotEmpty(t, tcpMapping.GetAuthToken(), "snapshot mapping must include per-proxy auth token")
}

func TestIntegration_SyncMappings_BackPressure(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	// Add enough services to guarantee multiple batches (default batch size 500).
	addServicesToStore(t, setup, 600, "test.proxy.io")

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.SyncMappings(ctx)
	require.NoError(t, err)

	err = stream.Send(&proto.SyncMappingsRequest{
		Msg: &proto.SyncMappingsRequest_Init{
			Init: &proto.SyncMappingsInit{
				ProxyId: "sync-proxy-backpressure",
				Version: "test-v1",
				Address: "test.proxy.io",
			},
		},
	})
	require.NoError(t, err)

	// Strategy: receive batch 1, then hold for a significant delay before
	// acking. If back-pressure works, batch 2 cannot arrive until after
	// the ack is sent — so its receive timestamp must be >= the ack
	// timestamp. If management were fire-and-forget, all batches would
	// already be buffered in the gRPC transport and batch 2 would arrive
	// well before the ack time.
	const ackDelay = 300 * time.Millisecond

	type batchEvent struct {
		recvAt time.Time
		ackAt  time.Time
		count  int
	}
	var batches []batchEvent
	var totalMappings int

	for {
		msg, err := stream.Recv()
		require.NoError(t, err)

		recvAt := time.Now()
		totalMappings += len(msg.GetMapping())

		// Delay the ack on non-final batches to create a measurable gap.
		if !msg.GetInitialSyncComplete() {
			time.Sleep(ackDelay)
		}

		ackAt := time.Now()
		batches = append(batches, batchEvent{
			recvAt: recvAt,
			ackAt:  ackAt,
			count:  len(msg.GetMapping()),
		})

		err = stream.Send(&proto.SyncMappingsRequest{
			Msg: &proto.SyncMappingsRequest_Ack{Ack: &proto.SyncMappingsAck{}},
		})
		require.NoError(t, err)

		if msg.GetInitialSyncComplete() {
			break
		}
	}

	// 2 original + 600 added = 602 services total.
	assert.Equal(t, 602, totalMappings, "should receive all 602 mappings")
	require.GreaterOrEqual(t, len(batches), 2, "need at least 2 batches to verify back-pressure")

	// For every batch after the first, its receive time must be after the
	// previous batch's ack time. This proves management waited for the ack
	// before sending the next batch.
	for i := 1; i < len(batches); i++ {
		prevAckAt := batches[i-1].ackAt
		thisRecvAt := batches[i].recvAt
		assert.True(t, !thisRecvAt.Before(prevAckAt),
			"batch %d received at %v, but batch %d was acked at %v — "+
				"management sent the next batch before receiving the ack",
			i, thisRecvAt, i-1, prevAckAt)
	}
}

func TestIntegration_SyncMappings_IncrementalUpdate(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.SyncMappings(ctx)
	require.NoError(t, err)

	err = stream.Send(&proto.SyncMappingsRequest{
		Msg: &proto.SyncMappingsRequest_Init{
			Init: &proto.SyncMappingsInit{
				ProxyId: "sync-proxy-incremental",
				Version: "test-v1",
				Address: "test.proxy.io",
			},
		},
	})
	require.NoError(t, err)

	// Drain initial snapshot.
	for {
		msg, err := stream.Recv()
		require.NoError(t, err)

		err = stream.Send(&proto.SyncMappingsRequest{
			Msg: &proto.SyncMappingsRequest_Ack{Ack: &proto.SyncMappingsAck{}},
		})
		require.NoError(t, err)

		if msg.GetInitialSyncComplete() {
			break
		}
	}

	// Now send an incremental update via the management server.
	setup.proxyService.SendServiceUpdate(&proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{{
			Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
			Id:        "rp-1",
			AccountId: "test-account-1",
			Domain:    "app1.test.proxy.io",
		}},
	})

	// Receive the incremental update on the sync stream.
	msg, err := stream.Recv()
	require.NoError(t, err)
	require.NotEmpty(t, msg.GetMapping())
	assert.Equal(t, "rp-1", msg.GetMapping()[0].GetId())
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, msg.GetMapping()[0].GetType())
}

func TestIntegration_SyncMappings_MixedProxyVersions(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Old proxy uses GetMappingUpdate.
	legacyStream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId: "legacy-proxy",
		Version: "old-v1",
		Address: "test.proxy.io",
	})
	require.NoError(t, err)

	var legacyMappings []*proto.ProxyMapping
	for {
		msg, err := legacyStream.Recv()
		require.NoError(t, err)
		legacyMappings = append(legacyMappings, msg.GetMapping()...)
		if msg.GetInitialSyncComplete() {
			break
		}
	}

	// New proxy uses SyncMappings.
	syncStream, err := client.SyncMappings(ctx)
	require.NoError(t, err)

	err = syncStream.Send(&proto.SyncMappingsRequest{
		Msg: &proto.SyncMappingsRequest_Init{
			Init: &proto.SyncMappingsInit{
				ProxyId: "new-proxy",
				Version: "new-v2",
				Address: "test.proxy.io",
			},
		},
	})
	require.NoError(t, err)

	var syncMappings []*proto.ProxyMapping
	for {
		msg, err := syncStream.Recv()
		require.NoError(t, err)
		syncMappings = append(syncMappings, msg.GetMapping()...)

		err = syncStream.Send(&proto.SyncMappingsRequest{
			Msg: &proto.SyncMappingsRequest_Ack{Ack: &proto.SyncMappingsAck{}},
		})
		require.NoError(t, err)

		if msg.GetInitialSyncComplete() {
			break
		}
	}

	// Both should receive the same set of mappings.
	assert.Equal(t, len(legacyMappings), len(syncMappings),
		"legacy and sync proxies should receive the same number of mappings")

	legacyIDs := make(map[string]bool)
	for _, m := range legacyMappings {
		legacyIDs[m.GetId()] = true
	}
	for _, m := range syncMappings {
		assert.True(t, legacyIDs[m.GetId()],
			"mapping %s should be present in both streams", m.GetId())
	}

	// Both proxies should be connected.
	proxies := setup.proxyService.GetConnectedProxies()
	assert.Contains(t, proxies, "legacy-proxy")
	assert.Contains(t, proxies, "new-proxy")

	// Both should receive incremental updates.
	setup.proxyService.SendServiceUpdate(&proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{{
			Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
			Id:        "rp-1",
			AccountId: "test-account-1",
			Domain:    "app1.test.proxy.io",
		}},
	})

	// Legacy proxy receives via GetMappingUpdateResponse.
	legacyMsg, err := legacyStream.Recv()
	require.NoError(t, err)
	assert.Equal(t, "rp-1", legacyMsg.GetMapping()[0].GetId())

	// Sync proxy receives via SyncMappingsResponse.
	syncMsg, err := syncStream.Recv()
	require.NoError(t, err)
	assert.Equal(t, "rp-1", syncMsg.GetMapping()[0].GetId())
}

func TestIntegration_SyncMappings_Reconnect(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)
	proxyID := "sync-proxy-reconnect"

	receiveMappings := func() []*proto.ProxyMapping {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		stream, err := client.SyncMappings(ctx)
		require.NoError(t, err)

		err = stream.Send(&proto.SyncMappingsRequest{
			Msg: &proto.SyncMappingsRequest_Init{
				Init: &proto.SyncMappingsInit{
					ProxyId: proxyID,
					Version: "test-v1",
					Address: "test.proxy.io",
				},
			},
		})
		require.NoError(t, err)

		var mappings []*proto.ProxyMapping
		for {
			msg, err := stream.Recv()
			require.NoError(t, err)
			mappings = append(mappings, msg.GetMapping()...)

			err = stream.Send(&proto.SyncMappingsRequest{
				Msg: &proto.SyncMappingsRequest_Ack{Ack: &proto.SyncMappingsAck{}},
			})
			require.NoError(t, err)

			if msg.GetInitialSyncComplete() {
				break
			}
		}
		return mappings
	}

	first := receiveMappings()
	time.Sleep(100 * time.Millisecond)
	second := receiveMappings()

	assert.Equal(t, len(first), len(second),
		"should receive same mappings on reconnect")

	firstIDs := make(map[string]bool)
	for _, m := range first {
		firstIDs[m.GetId()] = true
	}
	for _, m := range second {
		assert.True(t, firstIDs[m.GetId()],
			"mapping %s should be present in both connections", m.GetId())
	}
}

// --- Fallback tests: old management returns Unimplemented ---

// unimplementedProxyServer embeds UnimplementedProxyServiceServer so
// SyncMappings returns codes.Unimplemented while GetMappingUpdate works.
type unimplementedSyncServer struct {
	proto.UnimplementedProxyServiceServer
	getMappingCalls atomic.Int32
}

func (s *unimplementedSyncServer) GetMappingUpdate(_ *proto.GetMappingUpdateRequest, stream proto.ProxyService_GetMappingUpdateServer) error {
	s.getMappingCalls.Add(1)
	return stream.Send(&proto.GetMappingUpdateResponse{
		Mapping:             []*proto.ProxyMapping{{Id: "svc-1", AccountId: "acct-1", Domain: "example.com"}},
		InitialSyncComplete: true,
	})
}

func TestIntegration_FallbackToGetMappingUpdate(t *testing.T) {
	// Start a gRPC server that does NOT implement SyncMappings.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &unimplementedSyncServer{}
	grpcServer := grpc.NewServer()
	proto.RegisterProxyServiceServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	// Try SyncMappings — should get Unimplemented.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream, err := client.SyncMappings(ctx)
	require.NoError(t, err)

	err = stream.Send(&proto.SyncMappingsRequest{
		Msg: &proto.SyncMappingsRequest_Init{
			Init: &proto.SyncMappingsInit{
				ProxyId: "test-proxy",
				Address: "test.example.com",
			},
		},
	})
	require.NoError(t, err)

	_, err = stream.Recv()
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code(),
		"unimplemented SyncMappings should return Unimplemented code")

	// isSyncUnimplemented should detect this.
	assert.True(t, isSyncUnimplemented(err))

	// The actual fallback: GetMappingUpdate should work.
	legacyStream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId: "test-proxy",
		Address: "test.example.com",
	})
	require.NoError(t, err)

	msg, err := legacyStream.Recv()
	require.NoError(t, err)
	assert.True(t, msg.GetInitialSyncComplete())
	assert.Len(t, msg.GetMapping(), 1)
	assert.Equal(t, int32(1), srv.getMappingCalls.Load())
}

func TestIsSyncUnimplemented(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"non-grpc error", errors.New("random"), false},
		{"grpc internal", grpcstatus.Error(codes.Internal, "fail"), false},
		{"grpc unavailable", grpcstatus.Error(codes.Unavailable, "fail"), false},
		{"grpc unimplemented", grpcstatus.Error(codes.Unimplemented, "method not found"), true},
		{
			"wrapped unimplemented",
			fmt.Errorf("create sync stream: %w", grpcstatus.Error(codes.Unimplemented, "nope")),
			// grpc/status.FromError unwraps in recent versions of grpc-go.
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSyncUnimplemented(tt.err))
		})
	}
}

// addServicesToStore adds n extra services to the test store for the given cluster.
func addServicesToStore(t *testing.T, setup *integrationTestSetup, n int, cluster string) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		svc := &service.Service{
			ID:           fmt.Sprintf("extra-svc-%d", i),
			AccountID:    "test-account-1",
			Name:         fmt.Sprintf("Extra Service %d", i),
			Domain:       fmt.Sprintf("extra-%d.test.proxy.io", i),
			ProxyCluster: cluster,
			Enabled:      true,
			Targets: []*service.Target{{
				Path:       strPtr("/"),
				Host:       fmt.Sprintf("10.0.1.%d", i%256),
				Port:       8080,
				Protocol:   "http",
				TargetId:   fmt.Sprintf("peer-extra-%d", i),
				TargetType: "peer",
				Enabled:    true,
			}},
		}
		require.NoError(t, setup.store.CreateService(ctx, svc))
	}
}
