package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

// Test that an extension's interceptors and service registration are actually
// wired onto a real in-process gRPC server via the helpers, and that shutdown
// hooks run. This validates the load-bearing assumption that
// grpc.ChainUnaryInterceptor is additive (extension interceptors run in
// addition to any base chain).
func TestGRPCExtensionAppliedToServer(t *testing.T) {
	var unaryCalls atomic.Int32
	var streamShutdownCalled atomic.Bool

	ext := GRPCExtension{
		Register: func(reg grpc.ServiceRegistrar) {
			healthgrpc.RegisterHealthServer(reg, health.NewServer())
		},
		UnaryInterceptors: []grpc.UnaryServerInterceptor{
			func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				unaryCalls.Add(1)
				return handler(ctx, req)
			},
		},
		Shutdown: func() { streamShutdownCalled.Store(true) },
	}
	exts := []GRPCExtension{ext}

	// Base options mimic GRPCServer(): a pre-existing chain the extension appends to.
	var baseUnaryCalls atomic.Int32
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			baseUnaryCalls.Add(1)
			return handler(ctx, req)
		}),
	}
	opts = appendExtensionInterceptors(opts, exts)

	srv := grpc.NewServer(opts...)
	registerExtensions(srv, exts)

	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthgrpc.NewHealthClient(conn).Check(context.Background(), &healthgrpc.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check via extension-registered service failed: %v", err)
	}
	if baseUnaryCalls.Load() != 1 {
		t.Errorf("base interceptor calls = %d, want 1 (base chain must be preserved)", baseUnaryCalls.Load())
	}
	if unaryCalls.Load() != 1 {
		t.Errorf("extension interceptor calls = %d, want 1", unaryCalls.Load())
	}

	runExtensionShutdownHooks(exts)
	if !streamShutdownCalled.Load() {
		t.Error("extension shutdown hook was not called")
	}
}

func TestRegisterGRPCExtensionAccumulates(t *testing.T) {
	s := &BaseServer{}
	s.RegisterGRPCExtension(GRPCExtension{})
	s.RegisterGRPCExtension(GRPCExtension{})
	if len(s.grpcExtensions) != 2 {
		t.Fatalf("grpcExtensions len = %d, want 2", len(s.grpcExtensions))
	}
}
