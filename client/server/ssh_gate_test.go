package server

import (
	"context"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// ctxWithIdentity builds a request context carrying the identity the transport
// credentials would have attached.
func ctxWithIdentity(id ipcauth.Identity) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: ipcauth.AuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
			Identity:       id,
		},
	})
}

// unprivUID is deliberately not this process's own uid. An unprivileged daemon
// treats a caller sharing its identity as privileged (rootless containers), and
// the test binary would otherwise stand in for both the daemon and the caller.
// os.Geteuid returns -1 on Windows, where identities are SIDs instead and this is
// unused.
var unprivUID = uint32(os.Geteuid() + 1)

// The fabricated identities have to be shaped like the platform's: a uid says
// nothing on Windows, and a zero uid there would read as root and be privileged.
func rootCtx() context.Context { return ctxWithIdentity(privilegedIdentity()) }
func userCtx() context.Context { return ctxWithIdentity(unprivilegedIdentity()) }

func privilegedIdentity() ipcauth.Identity {
	if runtime.GOOS == "windows" {
		// LocalSystem, which is what the Windows service account is.
		return ipcauth.Identity{SID: "S-1-5-18"}
	}
	return ipcauth.Identity{UID: 0}
}

func unprivilegedIdentity() ipcauth.Identity {
	if runtime.GOOS == "windows" {
		// A plain user SID: no groups, so no BUILTIN\Administrators, and not
		// elevated.
		return ipcauth.Identity{SID: "S-1-5-21-1-2-3-1001"}
	}
	return ipcauth.Identity{UID: unprivUID, GID: unprivUID}
}
func noIdentityCtx() context.Context { return context.Background() }

func boolPtr(v bool) *bool { return &v }

func strPtr(v string) *string { return &v }

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func assertDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the change to be refused, got nil")
	}
	st := gstatus.Convert(err)
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", st.Code())
	}
	// The refusal must be machine-readable: the CLI and the UI render the
	// summary and command from the detail rather than parsing the message.
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if got, ok := d.(*errdetails.ErrorInfo); ok {
			info = got
		}
	}
	if info == nil {
		t.Fatal("refusal carries no ErrorInfo detail")
	}
	if info.GetReason() != ipcauth.ErrorReasonPrivilegeRequired || info.GetDomain() != ipcauth.ErrorDomain {
		t.Fatalf("detail = %s/%s, want %s/%s", info.GetDomain(), info.GetReason(), ipcauth.ErrorDomain, ipcauth.ErrorReasonPrivilegeRequired)
	}
	if info.GetMetadata()[ipcauth.ErrorMetaSummary] == "" {
		t.Error("detail carries no summary")
	}
	if info.GetMetadata()[ipcauth.ErrorMetaCommand] == "" {
		t.Error("detail carries no command")
	}
}

func assertAllowed(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected the change to be allowed, got %v", err)
	}
}

func TestRequirePrivilegeForConfigChange_SSHFlags(t *testing.T) {
	tests := []struct {
		name       string
		stored     *profilemanager.Config
		change     privilegedConfigChange
		privileged bool
		wantDeny   bool
	}{
		{
			name:     "enabling the ssh server unprivileged is refused",
			stored:   &profilemanager.Config{ServerSSHAllowed: boolPtr(false)},
			change:   privilegedConfigChange{serverSSHAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:       "enabling the ssh server as root is allowed",
			stored:     &profilemanager.Config{ServerSSHAllowed: boolPtr(false)},
			change:     privilegedConfigChange{serverSSHAllowed: boolPtr(true)},
			privileged: true,
		},
		{
			name:   "restating an already enabled ssh server is not a change",
			stored: &profilemanager.Config{ServerSSHAllowed: boolPtr(true)},
			change: privilegedConfigChange{serverSSHAllowed: boolPtr(true)},
		},
		{
			name:   "turning the ssh server off is not guarded",
			stored: &profilemanager.Config{ServerSSHAllowed: boolPtr(true)},
			change: privilegedConfigChange{serverSSHAllowed: boolPtr(false)},
		},
		{
			name:     "a profile with no config yet counts as off, so enabling is refused",
			stored:   nil,
			change:   privilegedConfigChange{serverSSHAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:     "enabling ssh root login unprivileged is refused",
			stored:   &profilemanager.Config{EnableSSHRoot: boolPtr(false)},
			change:   privilegedConfigChange{enableSSHRoot: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:   "restating ssh root login is not a change",
			stored: &profilemanager.Config{EnableSSHRoot: boolPtr(true)},
			change: privilegedConfigChange{enableSSHRoot: boolPtr(true)},
		},
		{
			name:   "turning ssh root login off is not guarded",
			stored: &profilemanager.Config{EnableSSHRoot: boolPtr(true)},
			change: privilegedConfigChange{enableSSHRoot: boolPtr(false)},
		},
		{
			name:     "disabling ssh authentication unprivileged is refused",
			stored:   &profilemanager.Config{DisableSSHAuth: boolPtr(false)},
			change:   privilegedConfigChange{disableSSHAuth: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:   "re-enabling ssh authentication is not guarded",
			stored: &profilemanager.Config{DisableSSHAuth: boolPtr(true)},
			change: privilegedConfigChange{disableSSHAuth: boolPtr(false)},
		},
		{
			name:     "enabling remote jobs unprivileged is refused",
			stored:   &profilemanager.Config{RemoteJobsAllowed: boolPtr(false)},
			change:   privilegedConfigChange{remoteJobsAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:       "enabling remote jobs as root is allowed",
			stored:     &profilemanager.Config{RemoteJobsAllowed: boolPtr(false)},
			change:     privilegedConfigChange{remoteJobsAllowed: boolPtr(true)},
			privileged: true,
		},
		{
			name:     "a profile with no config yet counts as off, so enabling remote jobs is refused",
			stored:   nil,
			change:   privilegedConfigChange{remoteJobsAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:   "restating already-enabled remote jobs is not a change",
			stored: &profilemanager.Config{RemoteJobsAllowed: boolPtr(true)},
			change: privilegedConfigChange{remoteJobsAllowed: boolPtr(true)},
		},
		{
			name:   "turning remote jobs off is not guarded",
			stored: &profilemanager.Config{RemoteJobsAllowed: boolPtr(true)},
			change: privilegedConfigChange{remoteJobsAllowed: boolPtr(false)},
		},
		{
			name:   "a request that touches none of the guarded fields is allowed",
			stored: &profilemanager.Config{ServerSSHAllowed: boolPtr(false)},
			change: privilegedConfigChange{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := userCtx()
			if tt.privileged {
				ctx = rootCtx()
			}
			err := requirePrivilegeForConfigChange(ctx, tt.stored, tt.change)
			if tt.wantDeny {
				assertDenied(t, err)
				return
			}
			assertAllowed(t, err)
		})
	}
}

func TestRequirePrivilegeForConfigChange_LocalMetrics(t *testing.T) {
	exposed := &profilemanager.Config{LocalMetricsEnabled: true, LocalMetricsAddress: "0.0.0.0:9191"}

	tests := []struct {
		name       string
		stored     *profilemanager.Config
		change     privilegedConfigChange
		privileged bool
		wantDeny   bool
	}{
		{
			name:     "binding a non-loopback address unprivileged is refused",
			stored:   &profilemanager.Config{},
			change:   privilegedConfigChange{enableLocalMetrics: boolPtr(true), localMetricsAddress: strPtr("0.0.0.0:9191")},
			wantDeny: true,
		},
		{
			name:       "binding a non-loopback address as root is allowed",
			stored:     &profilemanager.Config{},
			change:     privilegedConfigChange{enableLocalMetrics: boolPtr(true), localMetricsAddress: strPtr("0.0.0.0:9191")},
			privileged: true,
		},
		{
			name:   "enabling on the default loopback address is not guarded",
			stored: &profilemanager.Config{},
			change: privilegedConfigChange{enableLocalMetrics: boolPtr(true)},
		},
		{
			name:   "enabling on an explicit loopback address is not guarded",
			stored: &profilemanager.Config{},
			change: privilegedConfigChange{enableLocalMetrics: boolPtr(true), localMetricsAddress: strPtr("127.0.0.1:9999")},
		},
		{
			name:   "enabling on the IPv6 loopback address is not guarded",
			stored: &profilemanager.Config{},
			change: privilegedConfigChange{enableLocalMetrics: boolPtr(true), localMetricsAddress: strPtr("[::1]:9191")},
		},
		{
			// The address alone does nothing while the endpoint stays off.
			name:   "a non-loopback address without enabling is not guarded",
			stored: &profilemanager.Config{},
			change: privilegedConfigChange{localMetricsAddress: strPtr("0.0.0.0:9191")},
		},
		{
			name:     "widening an already enabled loopback endpoint is refused",
			stored:   &profilemanager.Config{LocalMetricsEnabled: true, LocalMetricsAddress: "127.0.0.1:9191"},
			change:   privilegedConfigChange{localMetricsAddress: strPtr("0.0.0.0:9191")},
			wantDeny: true,
		},
		{
			name:   "restating an already exposed endpoint is not a change",
			stored: exposed,
			change: privilegedConfigChange{enableLocalMetrics: boolPtr(true), localMetricsAddress: strPtr("0.0.0.0:9191")},
		},
		{
			name:   "turning an exposed endpoint off is not guarded",
			stored: exposed,
			change: privilegedConfigChange{enableLocalMetrics: boolPtr(false)},
		},
		{
			name:     "re-enabling an exposed endpoint that was turned off is refused",
			stored:   &profilemanager.Config{LocalMetricsEnabled: false, LocalMetricsAddress: "0.0.0.0:9191"},
			change:   privilegedConfigChange{enableLocalMetrics: boolPtr(true)},
			wantDeny: true,
		},
		{
			// Fail closed: an address that cannot be parsed is not confirmed loopback.
			name:     "an unparseable address is refused",
			stored:   &profilemanager.Config{},
			change:   privilegedConfigChange{enableLocalMetrics: boolPtr(true), localMetricsAddress: strPtr("not-an-address")},
			wantDeny: true,
		},
		{
			name:     "a profile with no config yet counts as off, so exposing is refused",
			stored:   nil,
			change:   privilegedConfigChange{enableLocalMetrics: boolPtr(true), localMetricsAddress: strPtr("0.0.0.0:9191")},
			wantDeny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := userCtx()
			if tt.privileged {
				ctx = rootCtx()
			}
			err := requirePrivilegeForConfigChange(ctx, tt.stored, tt.change)
			if tt.wantDeny {
				assertDenied(t, err)
				return
			}
			assertAllowed(t, err)
		})
	}
}

func TestRequirePrivilegeForConfigChange_ManagementURL(t *testing.T) {
	sshOn := func(raw string) *profilemanager.Config {
		return &profilemanager.Config{ServerSSHAllowed: boolPtr(true), ManagementURL: mustURL(t, raw)}
	}
	sshOff := func(raw string) *profilemanager.Config {
		return &profilemanager.Config{ServerSSHAllowed: boolPtr(false), ManagementURL: mustURL(t, raw)}
	}

	tests := []struct {
		name       string
		stored     *profilemanager.Config
		requested  string
		privileged bool
		wantDeny   bool
	}{
		{
			name:      "moving the binding while ssh is enabled is refused",
			stored:    sshOn("https://api.netbird.io:443"),
			requested: "https://attacker.example.com:443",
			wantDeny:  true,
		},
		{
			name:       "moving the binding as root is allowed",
			stored:     sshOn("https://api.netbird.io:443"),
			requested:  "https://selfhosted.example.com:443",
			privileged: true,
		},
		{
			name:      "the same url restated is not a change",
			stored:    sshOn("https://api.netbird.io:443"),
			requested: "https://api.netbird.io:443",
		},
		{
			name:      "an equivalent spelling of the same url is not a change",
			stored:    sshOn("https://api.netbird.io:443"),
			requested: "https://api.netbird.io",
		},
		{
			name:      "an equivalent spelling with an explicit http port is not a change",
			stored:    sshOn("http://mgmt.internal:80"),
			requested: "http://mgmt.internal",
		},
		{
			name:      "a different port on the same host is a change",
			stored:    sshOn("https://api.netbird.io:443"),
			requested: "https://api.netbird.io:8443",
			wantDeny:  true,
		},
		{
			name:      "a different scheme on the same host is a change",
			stored:    sshOn("https://mgmt.internal:443"),
			requested: "http://mgmt.internal:443",
			wantDeny:  true,
		},
		{
			name:      "with ssh disabled the binding is not guarded at all",
			stored:    sshOff("https://api.netbird.io:443"),
			requested: "https://attacker.example.com:443",
		},
		{
			name:      "an unparseable url fails closed",
			stored:    sshOn("https://api.netbird.io:443"),
			requested: "ht tp://%zz",
			wantDeny:  true,
		},
		{
			name:      "an empty url leaves the binding alone",
			stored:    sshOn("https://api.netbird.io:443"),
			requested: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := userCtx()
			if tt.privileged {
				ctx = rootCtx()
			}
			err := requirePrivilegeForConfigChange(ctx, tt.stored, privilegedConfigChange{managementURL: tt.requested})
			if tt.wantDeny {
				assertDenied(t, err)
				return
			}
			assertAllowed(t, err)
		})
	}
}

// A caller the daemon cannot identify must be refused, not trusted: that is the
// state on a TCP daemon socket, where no peer credentials exist.
func TestRequirePrivilegeForConfigChange_UnidentifiedCallerIsRefused(t *testing.T) {
	err := requirePrivilegeForConfigChange(noIdentityCtx(),
		&profilemanager.Config{ServerSSHAllowed: boolPtr(false)},
		privilegedConfigChange{serverSSHAllowed: boolPtr(true)})
	assertDenied(t, err)

	// The guidance must point at the socket rather than at sudo, since elevating
	// would not help.
	st := gstatus.Convert(err)
	if !strings.Contains(st.Message(), "service install") {
		t.Errorf("message %q does not tell the operator how to fix the socket", st.Message())
	}
}

func TestRequirePrivilegeForDeregistration(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *profilemanager.Config
		privileged bool
		wantDeny   bool
	}{
		{
			name:     "deregistering while ssh is enabled is refused",
			cfg:      &profilemanager.Config{ServerSSHAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:       "deregistering while ssh is enabled is allowed for root",
			cfg:        &profilemanager.Config{ServerSSHAllowed: boolPtr(true)},
			privileged: true,
		},
		{
			name: "deregistering with ssh disabled is not guarded",
			cfg:  &profilemanager.Config{ServerSSHAllowed: boolPtr(false)},
		},
		{
			name: "deregistering a profile with no config is not guarded",
			cfg:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := userCtx()
			if tt.privileged {
				ctx = rootCtx()
			}
			err := requirePrivilegeForDeregistration(ctx, tt.cfg)
			if tt.wantDeny {
				assertDenied(t, err)
				return
			}
			assertAllowed(t, err)
		})
	}
}

// privilegedTestCtx is the context a handler-level test should use when it is
// standing in for a root/administrator caller. Tests that drive the handlers
// directly have no transport credentials, and the privileged-change gate refuses
// a caller it cannot identify.
func privilegedTestCtx() context.Context { return rootCtx() }
