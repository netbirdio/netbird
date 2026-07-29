//go:build linux || darwin || freebsd

package ipcauth

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// TestPeerIdentity_MatchesCurrentProcess connects to a real Unix socket and
// verifies the extracted UID/GID match the running process (both ends are us).
func TestPeerIdentity_MatchesCurrentProcess(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		id  Identity
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			done <- result{err: aerr}
			return
		}
		defer func() { _ = c.Close() }()
		id, ierr := PeerIdentity(c)
		done <- result{id: id, err: ierr}
	}()

	client, err := net.Dial("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	res := <-done
	require.NoError(t, res.err)
	assert.Equal(t, uint32(os.Getuid()), res.id.UID, "UID should match current process")
	assert.Equal(t, uint32(os.Getgid()), res.id.GID, "primary GID should match current process")
}

// TestPeerIdentity_NonUnixConn rejects non-Unix connections (fail closed).
func TestPeerIdentity_NonUnixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan error, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			done <- aerr
			return
		}
		defer func() { _ = c.Close() }()
		_, ierr := PeerIdentity(c)
		done <- ierr
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	assert.Error(t, <-done, "PeerIdentity must reject a non-Unix connection")
}

// TestGRPCRoundTrip_ServerCredsClientInsecure proves the transport contract end
// to end: a gRPC server using the peercred transport credentials still serves a
// plain insecure client (the CLI never changed), and the caller's kernel
// identity reaches the handler via IdentityFromContext.
func TestGRPCRoundTrip_ServerCredsClientInsecure(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rt.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)

	var gotUID uint32
	var gotOK bool
	srv := grpc.NewServer(
		grpc.Creds(NewTransportCredentials()),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			id, ok := IdentityFromContext(ctx)
			gotUID, gotOK = id.UID, ok
			return h(ctx, req)
		}),
	)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err, "insecure client must reach the peercred server")

	assert.True(t, gotOK, "handler must see a peer identity")
	assert.Equal(t, uint32(os.Getuid()), gotUID, "handler must see the caller's UID")
}
