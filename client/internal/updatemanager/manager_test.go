//go:build windows || darwin

package updatemanager

import (
	"context"
	"fmt"
	"path"
	"testing"
	"time"

	v "github.com/hashicorp/go-version"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	cProto "github.com/netbirdio/netbird/client/proto"
)

func Test_LatestVersion(t *testing.T) {
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
			name:                 "Shouldn't update initially, but should update as soon as latest version is fetched",
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

		m := NewManager(recorder, statemanager.New(tmpFile))
		m.update = mockUpdate
		m.currentVersion = c.daemonVersion
		m.Start(context.Background())
		m.SetVersion("latest", false)

		ver, _ := waitForUpdateEvent(sub, 500*time.Millisecond)
		triggeredInit := ver != ""
		if triggeredInit != c.shouldUpdateInit {
			t.Errorf("%s: Initial update trigger mismatch, expected %v, got %v", c.name, c.shouldUpdateInit, triggeredInit)
		}
		if triggeredInit && c.initialLatestVersion != nil && ver != c.initialLatestVersion.String() {
			t.Errorf("%s: Initial update version mismatch, expected %v, got %v", c.name, c.initialLatestVersion.String(), ver)
		}

		mockUpdate.latestVersion = c.latestVersion
		mockUpdate.onUpdate()

		ver, _ = waitForUpdateEvent(sub, 500*time.Millisecond)
		triggeredLater := ver != ""
		if triggeredLater != c.shouldUpdateLater {
			t.Errorf("%s: Later update trigger mismatch, expected %v, got %v", c.name, c.shouldUpdateLater, triggeredLater)
		}
		if triggeredLater && c.latestVersion != nil && ver != c.latestVersion.String() {
			t.Errorf("%s: Later update version mismatch, expected %v, got %v", c.name, c.latestVersion.String(), ver)
		}

		m.Stop()
	}
}

func Test_HandleUpdate(t *testing.T) {
	testMatrix := []struct {
		name            string
		daemonVersion   string
		latestVersion   *v.Version
		expectedVersion string
		shouldUpdate    bool
	}{
		{
			name:            "Install to a specific version should update regardless of if latestVersion is available yet",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "0.56.0",
			shouldUpdate:    true,
		},
		{
			name:            "Install to specific version should not update if version matches",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "0.55.0",
			shouldUpdate:    false,
		},
		{
			name:            "Install to specific version should not update if current version is newer",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "0.54.0",
			shouldUpdate:    false,
		},
		{
			name:            "Install to latest version should update if latest is newer",
			daemonVersion:   "0.55.0",
			latestVersion:   v.Must(v.NewSemver("0.56.0")),
			expectedVersion: "latest",
			shouldUpdate:    true,
		},
		{
			name:            "Install to latest version should not update if latest == current",
			daemonVersion:   "0.56.0",
			latestVersion:   v.Must(v.NewSemver("0.56.0")),
			expectedVersion: "latest",
			shouldUpdate:    false,
		},
		{
			name:            "Should not update if daemon version is invalid",
			daemonVersion:   "development",
			latestVersion:   v.Must(v.NewSemver("1.0.0")),
			expectedVersion: "latest",
			shouldUpdate:    false,
		},
		{
			name:            "Should not update if expecting latest and latest version is unavailable",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "latest",
			shouldUpdate:    false,
		},
		{
			name:            "Should not update if expected version is invalid",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "development",
			shouldUpdate:    false,
		},
	}
	for idx, c := range testMatrix {
		tmpFile := path.Join(t.TempDir(), fmt.Sprintf("update-test-%d.json", idx))
		recorder := peer.NewRecorder("")
		sub := recorder.SubscribeToEvents()
		defer recorder.UnsubscribeFromEvents(sub)

		m := NewManager(recorder, statemanager.New(tmpFile))
		m.update = &versionUpdateMock{latestVersion: c.latestVersion}
		m.currentVersion = c.daemonVersion
		m.Start(context.Background())
		m.SetVersion(c.expectedVersion, false)

		ver, _ := waitForUpdateEvent(sub, 500*time.Millisecond)
		updateTriggered := ver != ""

		if updateTriggered {
			if c.expectedVersion == "latest" && c.latestVersion != nil && ver != c.latestVersion.String() {
				t.Errorf("%s: Version mismatch, expected %v, got %v", c.name, c.latestVersion.String(), ver)
			} else if c.expectedVersion != "latest" && c.expectedVersion != "development" && ver != c.expectedVersion {
				t.Errorf("%s: Version mismatch, expected %v, got %v", c.name, c.expectedVersion, ver)
			}
		}

		if updateTriggered != c.shouldUpdate {
			t.Errorf("%s: Update trigger mismatch, expected %v, got %v", c.name, c.shouldUpdate, updateTriggered)
		}
		m.Stop()
	}
}

func Test_EnforcedMetadata(t *testing.T) {
	// Mode 1 (downloadOnly): no enforced metadata
	tmpFile := path.Join(t.TempDir(), "update-test-mode1.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(recorder, statemanager.New(tmpFile))
	m.update = &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m.currentVersion = "1.0.0"
	m.Start(context.Background())
	m.SetDownloadOnly()

	_, enforced := waitForUpdateEvent(sub, 500*time.Millisecond)
	if enforced {
		t.Error("Mode 1: expected no enforced metadata")
	}
	m.Stop()

	// Mode 2 (enforced, forceUpdate=false): enforced metadata present, no auto-install
	tmpFile2 := path.Join(t.TempDir(), "update-test-mode2.json")
	recorder2 := peer.NewRecorder("")
	sub2 := recorder2.SubscribeToEvents()
	defer recorder2.UnsubscribeFromEvents(sub2)

	m2 := NewManager(recorder2, statemanager.New(tmpFile2))
	m2.update = &versionUpdateMock{latestVersion: nil}
	m2.currentVersion = "1.0.0"
	m2.Start(context.Background())
	m2.SetVersion("1.0.1", false)

	ver, enforced2 := waitForUpdateEvent(sub2, 500*time.Millisecond)
	if ver == "" {
		t.Fatal("Mode 2: expected new_version_available event")
	}
	if !enforced2 {
		t.Error("Mode 2: expected enforced metadata")
	}
	m2.Stop()
}

// ensure the proto import is used
var _ = cProto.SystemEvent_INFO
