//go:build !windows && !darwin

package updater

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	v "github.com/hashicorp/go-version"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// On Linux, only Mode 1 (downloadOnly) is supported.
// SetVersion falls back to download-only because auto-update installation is not supported.

func Test_LatestVersion_Linux(t *testing.T) {
	testMatrix := []struct {
		name                 string
		daemonVersion        string
		initialLatestVersion *v.Version
		latestVersion        *v.Version
		shouldUpdateInit     bool
		shouldUpdateLater    bool
	}{
		{
			name:                 "Should notify again when a newer version arrives even within 5 minutes",
			daemonVersion:        "1.0.0",
			initialLatestVersion: v.Must(v.NewSemver("1.0.1")),
			latestVersion:        v.Must(v.NewSemver("1.0.2")),
			shouldUpdateInit:     true,
			shouldUpdateLater:    true,
		},
		{
			name:                 "Shouldn't notify initially, but should notify as soon as latest version is fetched",
			daemonVersion:        "1.0.0",
			initialLatestVersion: nil,
			latestVersion:        v.Must(v.NewSemver("1.0.1")),
			shouldUpdateInit:     false,
			shouldUpdateLater:    true,
		},
	}

	for idx, c := range testMatrix {
		mockUpdate := &versionUpdateMock{latestVersion: c.initialLatestVersion}
		tmpFile := path.Join(t.TempDir(), fmt.Sprintf("update-test-%d.json", idx))
		recorder := peer.NewRecorder("")
		sub := recorder.SubscribeToEvents()
		defer recorder.UnsubscribeFromEvents(sub)

		m := NewManager(context.Background(), recorder, statemanager.New(tmpFile))
		m.update = mockUpdate
		m.currentVersion = c.daemonVersion
		m.Start(context.Background())
		m.SetDownloadOnly()

		ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond)
		triggeredInit := ver != ""
		if enforced {
			t.Errorf("%s: Linux Mode 1 must never have enforced metadata", c.name)
		}
		if triggeredInit != c.shouldUpdateInit {
			t.Errorf("%s: Initial notify mismatch, expected %v, got %v", c.name, c.shouldUpdateInit, triggeredInit)
		}
		if triggeredInit && c.initialLatestVersion != nil && ver != c.initialLatestVersion.String() {
			t.Errorf("%s: Initial version mismatch, expected %v, got %v", c.name, c.initialLatestVersion.String(), ver)
		}

		mockUpdate.setLatestVersion(c.latestVersion)
		mockUpdate.onUpdate()

		ver, enforced = waitForUpdateEvent(sub, 500*time.Millisecond)
		triggeredLater := ver != ""
		if enforced {
			t.Errorf("%s: Linux Mode 1 must never have enforced metadata", c.name)
		}
		if triggeredLater != c.shouldUpdateLater {
			t.Errorf("%s: Later notify mismatch, expected %v, got %v", c.name, c.shouldUpdateLater, triggeredLater)
		}
		if triggeredLater && c.latestVersion != nil && ver != c.latestVersion.String() {
			t.Errorf("%s: Later version mismatch, expected %v, got %v", c.name, c.latestVersion.String(), ver)
		}

		m.Stop()
	}
}

func Test_SetVersion_FallsBackToDownloadOnly_Linux(t *testing.T) {
	tmpFile := path.Join(t.TempDir(), "update-test-fallback.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(context.Background(), recorder, statemanager.New(tmpFile))
	m.update = &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.5"))}
	m.currentVersion = "1.0.0"
	m.Start(context.Background())
	m.SetVersion("1.0.1", false)

	ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond)
	if ver != "1.0.5" {
		t.Fatalf("expected download-only event for fetched 1.0.5, got %q", ver)
	}
	if enforced {
		t.Error("Linux fallback must never have enforced metadata")
	}

	m.Stop()
}

// The installer here is a stub that fails at once, so the forced install path
// can run end to end in a test without installing anything.
func Test_SetVersion_ForceInstallsWithoutSubscriber_Linux(t *testing.T) {
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(context.Background(), recorder, statemanager.New(path.Join(t.TempDir(), "update-test-force-install.json")))
	m.update = &versionUpdateMock{}
	m.currentVersion = "1.0.0"
	m.autoUpdateSupported = func() bool { return true }
	defer m.Stop()

	// No UI has subscribed to daemon events, and the test never calls Start.
	m.SetVersion("1.0.1", true)

	event := waitForAnyEvent(sub, 2*time.Second)
	if event == nil || event.GetMessage() != "Updating client" {
		t.Fatalf("a forced directive newer than the current version must start an install without a UI subscriber, got %v", event)
	}

	// The stub installer's error proves RunInstallation itself was called.
	for event != nil && event.GetMessage() != "Auto-update failed" {
		event = waitForAnyEvent(sub, 2*time.Second)
	}
	if event == nil || !strings.Contains(event.GetUserMessage(), "unsupported platform") {
		t.Fatalf("the forced install must reach the installer, got %v", event)
	}
}
