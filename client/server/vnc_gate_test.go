package server

import (
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestRequirePrivilegeForConfigChange_VNCFlags(t *testing.T) {
	tests := []struct {
		name       string
		stored     *profilemanager.Config
		change     privilegedConfigChange
		privileged bool
		wantDeny   bool
	}{
		{
			name:     "enabling the vnc server unprivileged is refused",
			stored:   &profilemanager.Config{ServerVNCAllowed: boolPtr(false)},
			change:   privilegedConfigChange{serverVNCAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:       "enabling the vnc server as root is allowed",
			stored:     &profilemanager.Config{ServerVNCAllowed: boolPtr(false)},
			change:     privilegedConfigChange{serverVNCAllowed: boolPtr(true)},
			privileged: true,
		},
		{
			name:   "restating an already enabled vnc server is not a change",
			stored: &profilemanager.Config{ServerVNCAllowed: boolPtr(true)},
			change: privilegedConfigChange{serverVNCAllowed: boolPtr(true)},
		},
		{
			name:   "turning the vnc server off is not guarded",
			stored: &profilemanager.Config{ServerVNCAllowed: boolPtr(true)},
			change: privilegedConfigChange{serverVNCAllowed: boolPtr(false)},
		},
		{
			// Unlike SSH, a nil flag means off: the flag shipped with the server.
			name:     "a config written before vnc existed counts as off, so enabling is refused",
			stored:   &profilemanager.Config{},
			change:   privilegedConfigChange{serverVNCAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:     "a profile with no config yet counts as off, so enabling is refused",
			stored:   nil,
			change:   privilegedConfigChange{serverVNCAllowed: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:     "disabling the vnc approval prompt unprivileged is refused",
			stored:   &profilemanager.Config{DisableVNCApproval: boolPtr(false)},
			change:   privilegedConfigChange{disableVNCApproval: boolPtr(true)},
			wantDeny: true,
		},
		{
			name:       "disabling the vnc approval prompt as root is allowed",
			stored:     &profilemanager.Config{DisableVNCApproval: boolPtr(false)},
			change:     privilegedConfigChange{disableVNCApproval: boolPtr(true)},
			privileged: true,
		},
		{
			name:   "re-enabling the vnc approval prompt is not guarded",
			stored: &profilemanager.Config{DisableVNCApproval: boolPtr(true)},
			change: privilegedConfigChange{disableVNCApproval: boolPtr(false)},
		},
		{
			name:   "restating a disabled approval prompt is not a change",
			stored: &profilemanager.Config{DisableVNCApproval: boolPtr(true)},
			change: privilegedConfigChange{disableVNCApproval: boolPtr(true)},
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

// The management binding and deregistration guards protect either remote-access
// server, so the VNC server alone must arm them even with SSH off.
func TestRequirePrivilegeForConfigChange_ManagementURLWithVNCOnly(t *testing.T) {
	vncOnly := &profilemanager.Config{
		ServerSSHAllowed:   boolPtr(false),
		ServerVNCAllowed:   boolPtr(true),
		ManagementURL:      mustURL(t, "https://api.netbird.io:443"),
		DisableVNCApproval: boolPtr(false),
	}

	err := requirePrivilegeForConfigChange(userCtx(), vncOnly,
		privilegedConfigChange{managementURL: "https://attacker.example.com:443"})
	assertDenied(t, err)

	// The same move is the administrator's to make.
	assertAllowed(t, requirePrivilegeForConfigChange(rootCtx(), vncOnly,
		privilegedConfigChange{managementURL: "https://selfhosted.example.com:443"}))

	// Restating the stored binding is not a change, so it is never refused.
	assertAllowed(t, requirePrivilegeForConfigChange(userCtx(), vncOnly,
		privilegedConfigChange{managementURL: "https://api.netbird.io"}))
}

func TestRequirePrivilegeForDeregistration_VNCOnly(t *testing.T) {
	vncOnly := &profilemanager.Config{ServerSSHAllowed: boolPtr(false), ServerVNCAllowed: boolPtr(true)}

	assertDenied(t, requirePrivilegeForDeregistration(userCtx(), vncOnly))
	assertAllowed(t, requirePrivilegeForDeregistration(rootCtx(), vncOnly))

	bothOff := &profilemanager.Config{ServerSSHAllowed: boolPtr(false), ServerVNCAllowed: boolPtr(false)}
	assertAllowed(t, requirePrivilegeForDeregistration(userCtx(), bothOff))
}

// enabledRemoteAccessServer names the server in the refusal, so the user is told
// which one is holding the binding down. SSH wins when both are on: it is the
// more privileged of the two.
func TestEnabledRemoteAccessServer(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *profilemanager.Config
		wantServer string
		wantOn     bool
	}{
		{
			name:       "ssh only",
			cfg:        &profilemanager.Config{ServerSSHAllowed: boolPtr(true), ServerVNCAllowed: boolPtr(false)},
			wantServer: "SSH",
			wantOn:     true,
		},
		{
			name:       "vnc only",
			cfg:        &profilemanager.Config{ServerSSHAllowed: boolPtr(false), ServerVNCAllowed: boolPtr(true)},
			wantServer: "VNC",
			wantOn:     true,
		},
		{
			name:       "both on reports ssh",
			cfg:        &profilemanager.Config{ServerSSHAllowed: boolPtr(true), ServerVNCAllowed: boolPtr(true)},
			wantServer: "SSH",
			wantOn:     true,
		},
		{
			name: "both off",
			cfg:  &profilemanager.Config{ServerSSHAllowed: boolPtr(false), ServerVNCAllowed: boolPtr(false)},
		},
		{
			// A nil SSH flag means on (legacy configs), so it still arms the guard.
			name:       "legacy config with no flags at all reports ssh",
			cfg:        &profilemanager.Config{},
			wantServer: "SSH",
			wantOn:     true,
		},
		{
			name: "no config",
			cfg:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, on := enabledRemoteAccessServer(tt.cfg)
			if on != tt.wantOn || server != tt.wantServer {
				t.Fatalf("enabledRemoteAccessServer() = (%q, %v), want (%q, %v)", server, on, tt.wantServer, tt.wantOn)
			}
		})
	}
}
