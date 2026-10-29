//go:build !android && !ios

package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/upload-server/types"
)

func TestRegisterUILogRefusesUnidentifiedCaller(t *testing.T) {
	s := &Server{}

	_, err := s.RegisterUILog(noIdentityCtx(), &proto.RegisterUILogRequest{
		Path: filepath.Join(t.TempDir(), uiLogFileName),
	})

	if gstatus.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", gstatus.Code(err))
	}
}

func TestRegisterUILogRefusesForeignPath(t *testing.T) {
	secret := "/etc/shadow"
	if runtime.GOOS == "windows" {
		secret = `C:\Windows\System32\config\SAM`
	}

	tests := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"relative", filepath.Join("netbird", uiLogFileName)},
		{"another file", secret},
		{"directory of the log", t.TempDir()},
		{"unc path", `\\attacker\share\` + uiLogFileName},
		{"device path", `\\.\C:\` + uiLogFileName},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}

			_, err := s.RegisterUILog(userCtx(), &proto.RegisterUILogRequest{Path: tc.path})

			if gstatus.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", gstatus.Code(err))
			}
			if s.uiLogPath != "" {
				t.Fatalf("path %q was recorded despite the refusal", s.uiLogPath)
			}
		})
	}
}

func TestRegisterUILogRecordsPath(t *testing.T) {
	s := &Server{}
	path := filepath.Join(t.TempDir(), uiLogFileName)

	if _, err := s.RegisterUILog(userCtx(), &proto.RegisterUILogRequest{Path: path}); err != nil {
		t.Fatalf("register: %v", err)
	}

	if s.uiLogPath != path {
		t.Fatalf("path = %q, want %q", s.uiLogPath, path)
	}
}

// The UI log is opened as the bundle requester, so a second local user cannot
// collect a log they do not own, and an unidentified requester collects nothing.
func TestUILogOpenerBindsToRequester(t *testing.T) {
	path := filepath.Join(t.TempDir(), uiLogFileName)
	if err := os.WriteFile(path, []byte("log line"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	// A different unprivileged user than the file's owner: refused.
	if _, err := uiLogOpener(unprivilegedIdentity(), true)(path); err == nil {
		t.Fatal("expected a file the requester does not own to be refused")
	}

	// No verified identity: refused.
	if _, err := uiLogOpener(ipcauth.Identity{}, false)(path); err == nil {
		t.Fatal("expected an unidentified requester to be refused")
	}

	// The requester that owns the file: allowed. The test process created it, so
	// its own identity is the owner (and a privileged runner is exempt anyway).
	owner, err := ipcauth.CurrentProcessIdentity()
	if err != nil {
		t.Fatalf("current identity: %v", err)
	}
	f, err := uiLogOpener(owner, true)(path)
	if err != nil {
		t.Fatalf("expected the owning requester to be allowed, got %v", err)
	}
	_ = f.Close()
}

func TestRequirePrivilegeForUploadURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		insecure bool
		unprivOK bool
		invalid  bool
		rootAlso bool
	}{
		{name: "no upload", url: "", unprivOK: true},
		{name: "default service", url: types.DefaultBundleURL, unprivOK: true},
		{name: "default service, other path", url: "https://upload.debug.netbird.io/other", unprivOK: true},
		{name: "loopback exfiltration endpoint", url: "https://127.0.0.1:8080/upload-url", rootAlso: true},
		{name: "custom upload service", url: "https://attacker.example/upload-url", rootAlso: true},
		{name: "plaintext default host", url: "http://upload.debug.netbird.io/upload-url", invalid: true},
		{name: "plaintext custom host", url: "http://attacker.example/upload-url", invalid: true},
		{name: "unsupported scheme", url: "file:///etc/shadow", invalid: true},
		// insecure relaxes transport security; privileged only, whatever the host.
		{name: "insecure http custom", url: "http://selfhosted.local/upload-url", insecure: true, rootAlso: true},
		{name: "insecure https custom", url: "https://selfhosted.local/upload-url", insecure: true, rootAlso: true},
		{name: "insecure default host", url: types.DefaultBundleURL, insecure: true, rootAlso: true},
		// --insecure must not widen the URL to non-http(s) schemes or a hostless URL.
		{name: "insecure file scheme", url: "file:///etc/shadow", insecure: true, invalid: true},
		{name: "insecure hostless", url: "https:///upload-url", insecure: true, invalid: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := requirePrivilegeForUploadURL(userCtx(), tc.url, tc.insecure)

			switch {
			case tc.invalid:
				if gstatus.Code(err) != codes.InvalidArgument {
					t.Fatalf("code = %v, want InvalidArgument", gstatus.Code(err))
				}
				return
			case tc.unprivOK:
				assertAllowed(t, err)
				return
			default:
				assertDenied(t, err)
			}

			if tc.rootAlso {
				assertAllowed(t, requirePrivilegeForUploadURL(rootCtx(), tc.url, tc.insecure))
			}
		})
	}
}
