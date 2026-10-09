//go:build !android && !ios && !freebsd && !js

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/services"
)

// trayWithLocalizer builds the minimum Tray the message/title resolvers touch:
// they read t.loc and nothing else, so no app, window or daemon connection is
// needed. The shipped locale tree is used so the assertions below exercise the
// real bundles rather than a fixture.
func trayWithLocalizer(t *testing.T) *Tray {
	t.Helper()
	bundle, err := i18n.NewBundle(os.DirFS("i18n/locales"))
	require.NoError(t, err, "the shipped locale tree must load")
	return &Tray{loc: NewLocalizer(bundle, nil)}
}

func TestLocalizedEventMessageResolvesKey(t *testing.T) {
	tray := trayWithLocalizer(t)

	got := tray.localizedEventMessage(services.SystemEvent{
		MessageKey: string(proto.UserMsgExitNodeConnected),
		// A daemon always ships its English rendering too; the key must win.
		UserMessage: "should not be used",
	})
	assert.Equal(t, "Exit node connected.", got)
}

func TestLocalizedEventMessageSubstitutesArgs(t *testing.T) {
	tray := trayWithLocalizer(t)

	got := tray.localizedEventMessage(services.SystemEvent{
		MessageKey:  string(proto.UserMsgUpdateCompleted),
		MessageArgs: map[string]string{proto.ArgVersion: "0.60.1"},
	})
	assert.Equal(t, "Your NetBird client was auto-updated to version 0.60.1.", got)
}

// A daemon newer than the UI can publish a key this build has never heard of.
// Showing the raw key would be a visible regression, so the daemon's own English
// text has to win instead.
func TestLocalizedEventMessageFallsBackToDaemonText(t *testing.T) {
	tray := trayWithLocalizer(t)

	got := tray.localizedEventMessage(services.SystemEvent{
		MessageKey:  "event.somethingThisBuildNeverHeardOf",
		UserMessage: "A message from a newer daemon.",
	})
	assert.Equal(t, "A message from a newer daemon.", got)
}

// An old daemon sends no key at all, only userMessage.
func TestLocalizedEventMessageWithoutKey(t *testing.T) {
	tray := trayWithLocalizer(t)

	got := tray.localizedEventMessage(services.SystemEvent{UserMessage: "Legacy English text."})
	assert.Equal(t, "Legacy English text.", got)
}

func TestEventTitlePrefersTitleKey(t *testing.T) {
	tray := trayWithLocalizer(t)

	got := tray.eventTitle(services.SystemEvent{
		Severity: "critical",
		Category: "authentication",
		TitleKey: string(proto.TitleSessionWarning),
	})
	assert.Equal(t, "Session expires soon", got, "a title key must beat the composed title")
}

func TestEventTitleComposesFromSeverityAndCategory(t *testing.T) {
	tray := trayWithLocalizer(t)

	tests := []struct {
		name     string
		severity string
		category string
		want     string
	}{
		{"warning dns", "warning", "dns", "Warning: DNS"},
		{"critical system", "critical", "system", "Critical: System"},
		{"info network", "info", "network", "Info: Network"},
		{"error authentication", "error", "authentication", "Error: Authentication"},
		// Enum values this build does not know, and the empty severity/category
		// an event carries before the daemon fills them in.
		{"unknown severity", "apocalyptic", "dns", "Info: DNS"},
		{"unknown category", "warning", "quantum", "Warning: System"},
		{"empty", "", "", "Info: System"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tray.eventTitle(services.SystemEvent{Severity: tc.severity, Category: tc.category})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestShouldSkipSystemEvent(t *testing.T) {
	tests := []struct {
		name string
		ev   services.SystemEvent
		want bool
	}{
		{
			name: "update announcement handled by the tray updater",
			ev:   services.SystemEvent{Metadata: map[string]string{"new_version_available": "0.60.1"}},
			want: true,
		},
		{
			name: "install progress belongs to the progress window",
			ev:   services.SystemEvent{Metadata: map[string]string{"progress_window": "show"}},
			want: true,
		},
		{
			name: "the v6 half of a dual-stack default route is already toasted as v4",
			ev:   services.SystemEvent{Category: "network", Metadata: map[string]string{"network": "::/0"}},
			want: true,
		},
		{
			name: "the v4 default route is the one that toasts",
			ev:   services.SystemEvent{Category: "network", Metadata: map[string]string{"network": "0.0.0.0/0"}},
			want: false,
		},
		{
			// policy_applied used to be suppressed here while the tray toasted
			// off the paired config_changed event; it now carries its own keys.
			name: "mdm policy applied surfaces normally",
			ev: services.SystemEvent{
				MessageKey: string(proto.UserMsgMDMPolicyApplied),
				Metadata:   map[string]string{proto.MetadataTypeKey: proto.MetadataTypePolicyApplied},
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shouldSkipSystemEvent(tc.ev))
		})
	}
}
