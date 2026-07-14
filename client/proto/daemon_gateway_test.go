package proto

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gatewayruntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestGatewayServerRoutesCoverDaemonRPCs(t *testing.T) {
	mux := gatewayruntime.NewServeMux()
	if err := RegisterDaemonServiceHandlerServer(context.Background(), mux, UnimplementedDaemonServiceServer{}); err != nil {
		t.Fatalf("register daemon gateway server handlers: %v", err)
	}

	assertAllDaemonGatewayRoutesRegistered(t, mux)
}

func TestGatewayClientRoutesCoverDaemonRPCs(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	RegisterDaemonServiceServer(server, UnimplementedDaemonServiceServer{})
	go func() {
		if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("serve bufconn gRPC server: %v", err)
		}
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mux := gatewayruntime.NewServeMux()
	opts := []grpc.DialOption{
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if err := RegisterDaemonServiceHandlerFromEndpoint(ctx, mux, "passthrough:///bufnet", opts); err != nil {
		t.Fatalf("register daemon gateway client handlers: %v", err)
	}

	assertAllDaemonGatewayRoutesRegistered(t, mux)
}

func assertAllDaemonGatewayRoutesRegistered(t *testing.T, mux http.Handler) {
	t.Helper()
	for _, method := range DaemonService_ServiceDesc.Methods {
		assertGatewayRouteRegistered(t, mux, method.MethodName)
	}
	for _, stream := range DaemonService_ServiceDesc.Streams {
		assertGatewayRouteRegistered(t, mux, stream.StreamName)
	}
}

func assertGatewayRouteRegistered(t *testing.T, mux http.Handler, methodName string) {
	t.Helper()

	path := "/daemon.DaemonService/" + methodName
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	mux.ServeHTTP(res, req)

	if res.Code == http.StatusNotFound {
		t.Fatalf("gateway route for %s is not registered", methodName)
	}
}
