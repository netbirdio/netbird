package cmd

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

// startUnixGRPCServer starts a bare gRPC server listening on a unix socket at path
// and returns a stop function. No services are registered; the connectivity-state
// wait only cares about the transport becoming READY.
func startUnixGRPCServer(t *testing.T, path string) func() {
	t.Helper()
	lis, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	srv := grpc.NewServer()
	go func() { _ = srv.Serve(lis) }()
	return srv.Stop
}

func TestDialClientGRPCServer_ConnectsWhenServing(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nb.sock")
	stop := startUnixGRPCServer(t, sock)
	defer stop()

	conn, err := dialClientGRPCServer(context.Background(), "unix://"+sock, 5*time.Second)
	if err != nil {
		t.Fatalf("expected connection, got error: %v", err)
	}
	defer conn.Close()

	if state := conn.GetState(); state != connectivity.Ready {
		t.Fatalf("expected READY, got %s", state)
	}
}

// TestDialClientGRPCServer_WaitsForLateServer is the core regression test: the
// daemon socket appears only after the dial has already started, mirroring
// "netbird service start" immediately followed by "netbird up".
func TestDialClientGRPCServer_WaitsForLateServer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nb.sock")

	var stop func()
	timer := time.AfterFunc(1*time.Second, func() {
		stop = startUnixGRPCServer(t, sock)
	})
	defer timer.Stop()
	defer func() {
		if stop != nil {
			stop()
		}
	}()

	start := time.Now()
	conn, err := dialClientGRPCServer(context.Background(), "unix://"+sock, 10*time.Second)
	if err != nil {
		t.Fatalf("expected connection after late server start, got error: %v", err)
	}
	defer conn.Close()

	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("connected too fast (%s); server should not have been up yet", elapsed)
	}
	if state := conn.GetState(); state != connectivity.Ready {
		t.Fatalf("expected READY, got %s", state)
	}
}

// fakeStatusServer serves the Status RPC with a programmable response so we can
// exercise waitForDaemonStatus without spinning up a real engine.
type fakeStatusServer struct {
	proto.UnimplementedDaemonServiceServer
	resp func() *proto.StatusResponse
}

func (f *fakeStatusServer) Status(context.Context, *proto.StatusRequest) (*proto.StatusResponse, error) {
	return f.resp(), nil
}

func startFakeStatusServer(t *testing.T, sock string, resp func() *proto.StatusResponse) func() {
	t.Helper()
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	srv := grpc.NewServer()
	proto.RegisterDaemonServiceServer(srv, &fakeStatusServer{resp: resp})
	go func() { _ = srv.Serve(lis) }()
	return srv.Stop
}

func dialFake(t *testing.T, sock string) proto.DaemonServiceClient {
	t.Helper()
	conn, err := dialClientGRPCServer(context.Background(), "unix://"+sock, 5*time.Second)
	if err != nil {
		t.Fatalf("dial fake daemon: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return proto.NewDaemonServiceClient(conn)
}

// New daemon that flips DaemonReady=true after a couple of polls: waitForDaemonStatus
// must block until the flag is set, then return.
func TestWaitForDaemonStatus_WaitsForDaemonReady(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nb.sock")
	var polls int32
	stop := startFakeStatusServer(t, sock, func() *proto.StatusResponse {
		n := atomic.AddInt32(&polls, 1)
		return &proto.StatusResponse{
			Status:      string(internal.StatusConnecting),
			DaemonReady: n >= 3, // ready only from the 3rd poll on
		}
	})
	defer stop()

	client := dialFake(t, sock)
	status, err := waitForDaemonStatus(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.GetDaemonReady() {
		t.Fatalf("expected DaemonReady=true, got false")
	}
	if got := atomic.LoadInt32(&polls); got < 3 {
		t.Fatalf("expected at least 3 polls before ready, got %d", got)
	}
}

// Older daemon that never sets DaemonReady but reports a healthy (Connected)
// status: waitForDaemonStatus must return promptly via the readiness fallback,
// not block for the whole grace window.
func TestWaitForDaemonStatus_OlderDaemonHealthyStatus(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nb.sock")
	stop := startFakeStatusServer(t, sock, func() *proto.StatusResponse {
		return &proto.StatusResponse{Status: string(internal.StatusConnected)} // DaemonReady unset
	})
	defer stop()

	client := dialFake(t, sock)
	start := time.Now()
	status, err := waitForDaemonStatus(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.GetDaemonReady() {
		t.Fatalf("expected DaemonReady=false from older daemon")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("returned too slowly (%s); healthy status should short-circuit the grace", elapsed)
	}
}

func TestDialClientGRPCServer_TimesOutWhenAbsent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "never.sock")

	start := time.Now()
	conn, err := dialClientGRPCServer(context.Background(), "unix://"+sock, 1*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("returned too early (%s); should have waited ~timeout", elapsed)
	}
}
