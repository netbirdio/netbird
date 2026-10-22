//go:build ios

package NetBirdSDK

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestIsLoginRequiredMissingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	c := &Client{cfgFile: path}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 2 {
		if !c.isLoginRequired(ctx) {
			t.Fatal("fresh profile must require login")
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("login check created a profile: %v", err)
	}
}

func TestIsLoginRequiredLocalErrorsAndOutage(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*profilemanager.Config)
		malformed bool
		want      bool
	}{
		{name: "existing profile offline", want: false},
		{name: "missing SSH key", mutate: func(c *profilemanager.Config) { c.SSHKey = "" }, want: true},
		{name: "missing WireGuard key", mutate: func(c *profilemanager.Config) { c.PrivateKey = "" }, want: true},
		{name: "invalid SSH key", mutate: func(c *profilemanager.Config) { c.SSHKey = "invalid" }, want: true},
		{name: "invalid WireGuard key", mutate: func(c *profilemanager.Config) { c.PrivateKey = "invalid" }, want: true},
		{name: "invalid management URL", mutate: func(c *profilemanager.Config) { c.ManagementURL = &url.URL{Scheme: "ftp", Host: "localhost"} }, want: true},
		{name: "malformed config", malformed: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			cfg, err := profilemanager.DirectUpdateOrCreateConfig(profilemanager.ConfigInput{ConfigPath: path, ManagementURL: "http://127.0.0.1:1"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.mutate != nil {
				tc.mutate(cfg)
			}
			if err := profilemanager.DirectWriteOutConfig(path, cfg); err != nil {
				t.Fatal(err)
			}
			if tc.malformed {
				if err := os.WriteFile(path, []byte("invalid json"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{cfgFile: path}
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Deterministic unavailable transport; no dependency on a live server.
			if got := c.isLoginRequired(ctx); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("login check changed stored credentials")
			}
			// tvOS supplies the same profile in memory instead of a file.
			if !tc.malformed {
				raw, err := profilemanager.ConfigToJSON(cfg)
				if err != nil {
					t.Fatal(err)
				}
				c = &Client{}
				if err := c.SetConfigFromJSON(raw); err != nil {
					t.Fatal(err)
				}
				if got := c.isLoginRequired(ctx); got != tc.want {
					t.Fatalf("preloaded: got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestIsLoginTransportError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{context.Canceled, true},
		{fmt.Errorf("dial: %w", context.DeadlineExceeded), true},
		{&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, true},
		{status.Error(codes.Unavailable, "offline"), true},
		{status.Error(codes.DeadlineExceeded, "timeout"), true},
		{status.Error(codes.Canceled, "canceled"), true},
		{status.Error(codes.PermissionDenied, "denied"), false},
		{status.Error(codes.InvalidArgument, "invalid"), false},
		{status.Error(codes.Internal, "server error"), false},
		{errors.New("invalid key"), false},
	} {
		if got := isLoginTransportError(tc.err); got != tc.want {
			t.Errorf("%v: got %v, want %v", tc.err, got, tc.want)
		}
	}
}

// An RPC outage after dialing must preserve an existing profile just like a
// dial failure. Exercise the real auth client, not a substituted verdict.
func TestIsLoginRequiredManagementOutage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	service := &unavailableManagement{}
	mgmProto.RegisterManagementServiceServer(server, service)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := profilemanager.DirectUpdateOrCreateConfig(profilemanager.ConfigInput{ConfigPath: path, ManagementURL: "http://" + listener.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := &Client{cfgFile: path}
	if c.isLoginRequired(ctx) {
		t.Fatal("management outage must not require browser login")
	}
	if service.calls.Load() == 0 {
		t.Fatal("management RPC was never reached")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("management outage changed credentials")
	}
}

type unavailableManagement struct {
	mgmProto.UnimplementedManagementServiceServer
	calls atomic.Int32
}

func (s *unavailableManagement) GetServerKey(context.Context, *mgmProto.Empty) (*mgmProto.ServerKeyResponse, error) {
	s.calls.Add(1)
	return nil, status.Error(codes.Unavailable, "management offline")
}
