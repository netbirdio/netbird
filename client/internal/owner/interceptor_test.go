package owner

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type mockOwnerConfig struct {
	uids []UID
	err  error
}

func (m *mockOwnerConfig) GetOwnerUIDs() []UID {
	return m.uids
}

func (m *mockOwnerConfig) AddOwnerUID(uid UID) error {
	if m.err != nil {
		return m.err
	}
	m.uids = append(m.uids, uid)
	return nil
}

func peerContext(uid UID) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"},
		AuthInfo: UnixAuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
			UID:            uid,
		},
	})
}

func noPeerContext() context.Context {
	return context.Background()
}

// withConsoleUID overrides the platform console-user lookup for a single test.
func withConsoleUID(t *testing.T, uid uint32, ok bool) {
	t.Helper()
	prev := consoleUIDLookup
	consoleUIDLookup = func() (uint32, bool) { return uid, ok }
	t.Cleanup(func() { consoleUIDLookup = prev })
}

func TestInterceptor_RootAlwaysAllowed(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	for _, method := range []string{
		"/daemon.DaemonService/Up",
		"/daemon.DaemonService/Status",
		"/daemon.DaemonService/Down",
	} {
		err := interceptor.authorize(peerContext(0), method)
		assert.NoError(t, err, "root should always be allowed for %s", method)
	}
}

func TestInterceptor_NoPeerCreds_AlwaysDenies(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	for _, method := range []string{
		"/daemon.DaemonService/Status",
		"/daemon.DaemonService/Up",
		"/daemon.DaemonService/SomeNewMethod",
	} {
		err := interceptor.authorize(noPeerContext(), method)
		require.Error(t, err, "method %s should be denied without peer creds", method)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	}
}

// TestInterceptor_LegacyMigration covers the nil-OwnerUIDs branch:
// pre-enforcement configs upgraded to this version. Any non-root local caller
// can claim on first call.
func TestInterceptor_LegacyMigration_AnyCallerClaims(t *testing.T) {
	withConsoleUID(t, 0, false) // no console; should not matter for nil
	cfg := &mockOwnerConfig{uids: nil}
	interceptor := NewInterceptor(cfg)

	// First call from any UID claims regardless of method.
	err := interceptor.authorize(peerContext(1000), "/daemon.DaemonService/Status")
	require.NoError(t, err)
	require.Equal(t, []UID{1000}, cfg.uids)

	// After claim, a different UID is denied.
	err = interceptor.authorize(peerContext(2000), "/daemon.DaemonService/Status")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestInterceptor_FreshInstall covers the empty-OwnerUIDs branch: console-user
// can claim, others denied.
func TestInterceptor_FreshInstall_ConsoleUserClaims(t *testing.T) {
	withConsoleUID(t, 1000, true)
	cfg := &mockOwnerConfig{uids: []UID{}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(1000), "/daemon.DaemonService/Status")
	require.NoError(t, err)
	require.Equal(t, []UID{1000}, cfg.uids)
}

func TestInterceptor_FreshInstall_NonConsoleDenied(t *testing.T) {
	withConsoleUID(t, 1000, true)
	cfg := &mockOwnerConfig{uids: []UID{}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(2000), "/daemon.DaemonService/Up")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, cfg.uids, "non-console caller must not claim")
}

func TestInterceptor_FreshInstall_NoConsole_Denied(t *testing.T) {
	withConsoleUID(t, 0, false)
	cfg := &mockOwnerConfig{uids: []UID{}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(1000), "/daemon.DaemonService/Up")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestInterceptor_OwnerUID_AllowsOwner(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(1000), "/daemon.DaemonService/Down")
	assert.NoError(t, err)
}

func TestInterceptor_OwnerUID_DeniesOther(t *testing.T) {
	withConsoleUID(t, 9999, true) // console-user TOFU should not apply once owners exist
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(2000), "/daemon.DaemonService/Down")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestInterceptor_MultipleOwners(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000, 2000}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(1000), "/daemon.DaemonService/Down")
	assert.NoError(t, err)

	err = interceptor.authorize(peerContext(2000), "/daemon.DaemonService/Up")
	assert.NoError(t, err)

	err = interceptor.authorize(peerContext(3000), "/daemon.DaemonService/Down")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestInterceptor_UnknownMethodRequiresOwner pins the safe-by-default invariant:
// any future RPC still goes through owner enforcement.
func TestInterceptor_UnknownMethodRequiresOwner(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(2000), "/daemon.DaemonService/SomeFutureMethod")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	err = interceptor.authorize(peerContext(1000), "/daemon.DaemonService/SomeFutureMethod")
	assert.NoError(t, err)
}

func TestInterceptor_ErrorMessageActionable(t *testing.T) {
	withConsoleUID(t, 9999, true)
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	err := interceptor.authorize(peerContext(2000), "/daemon.DaemonService/Down")
	require.Error(t, err)
	msg := status.Convert(err).Message()
	assert.Contains(t, msg, "sudo netbird")
	assert.Contains(t, msg, "owner add")
}

func TestInterceptor_UnaryIntegration(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	unary := interceptor.UnaryInterceptor()

	resp, err := unary(peerContext(1000), nil, &grpc.UnaryServerInfo{FullMethod: "/daemon.DaemonService/Down"}, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)

	_, err = unary(peerContext(2000), nil, &grpc.UnaryServerInfo{FullMethod: "/daemon.DaemonService/Down"}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestInterceptor_StreamIntegration(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	stream := interceptor.StreamInterceptor()

	called := false
	err := stream(nil, &mockServerStream{ctx: peerContext(1000)},
		&grpc.StreamServerInfo{FullMethod: "/daemon.DaemonService/SubscribeEvents"},
		func(srv any, stream grpc.ServerStream) error {
			called = true
			return nil
		})
	require.NoError(t, err)
	assert.True(t, called)

	err = stream(nil, &mockServerStream{ctx: peerContext(2000)},
		&grpc.StreamServerInfo{FullMethod: "/daemon.DaemonService/SubscribeEvents"},
		func(srv any, stream grpc.ServerStream) error {
			t.Fatal("handler should not be called")
			return nil
		})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context { return m.ctx }

// TestInterceptor_ProfileBypass pins that profile-management methods reach
// the handler regardless of active-profile ownership; the handler enforces
// per-target-profile auth itself.
func TestInterceptor_ProfileBypass(t *testing.T) {
	cfg := &mockOwnerConfig{uids: []UID{1000}}
	interceptor := NewInterceptor(cfg)

	// Caller UID 2000 is not an owner of the active profile but must be
	// allowed through for these methods.
	for _, method := range []string{
		"/daemon.DaemonService/AddProfile",
		"/daemon.DaemonService/ListProfiles",
		"/daemon.DaemonService/RemoveProfile",
		"/daemon.DaemonService/SwitchProfile",
	} {
		err := interceptor.authorize(peerContext(2000), method)
		assert.NoError(t, err, "profile method %s should bypass active-owner check", method)
	}

	// Without peer creds, even bypass methods are denied.
	for _, method := range []string{
		"/daemon.DaemonService/AddProfile",
		"/daemon.DaemonService/SwitchProfile",
	} {
		err := interceptor.authorize(noPeerContext(), method)
		require.Error(t, err, "bypass method %s still requires peer creds", method)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	}
}
