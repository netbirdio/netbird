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
)

type versionUpdateMock struct {
	latestVersion *v.Version
	onUpdate      func()
}

func (v versionUpdateMock) StopWatch() {}

func (v versionUpdateMock) SetDaemonVersion(newVersion string) bool {
	return false
}

func (v *versionUpdateMock) SetOnUpdateListener(updateFn func()) {
	v.onUpdate = updateFn
}

func (v versionUpdateMock) LatestVersion() *v.Version {
	return v.latestVersion
}

func (v versionUpdateMock) StartFetcher() {}

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
			name:                 "Should only trigger update once due to time between triggers being < 5 Minutes",
			daemonVersion:        "1.0.0",
			initialLatestVersion: v.Must(v.NewSemver("1.0.1")),
			latestVersion:        v.Must(v.NewSemver("1.0.2")),
			shouldUpdateInit:     true,
			shouldUpdateLater:    false,
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
		m, _ := newManager(peer.NewRecorder(""), statemanager.New(tmpFile))
		m.update = mockUpdate

		targetVersionChan := make(chan string, 1)

		m.triggerUpdateFn = func(ctx context.Context, targetVersion string) error {
			targetVersionChan <- targetVersion
			return nil
		}
		m.currentVersion = c.daemonVersion
		m.Start(context.Background())
		m.SetVersion("latest")
		var triggeredInit bool
		select {
		case targetVersion := <-targetVersionChan:
			if targetVersion != c.initialLatestVersion.String() {
				t.Errorf("%s: Initial update version mismatch, expected %v, got %v", c.name, c.initialLatestVersion.String(), targetVersion)
			}
			triggeredInit = true
		case <-time.After(10 * time.Millisecond):
			triggeredInit = false
		}
		if triggeredInit != c.shouldUpdateInit {
			t.Errorf("%s: Initial update trigger mismatch, expected %v, got %v", c.name, c.shouldUpdateInit, triggeredInit)
		}

		mockUpdate.latestVersion = c.latestVersion
		mockUpdate.onUpdate()

		var triggeredLater bool
		select {
		case targetVersion := <-targetVersionChan:
			if targetVersion != c.latestVersion.String() {
				t.Errorf("%s: Update version mismatch, expected %v, got %v", c.name, c.latestVersion.String(), targetVersion)
			}
			triggeredLater = true
		case <-time.After(10 * time.Millisecond):
			triggeredLater = false
		}
		if triggeredLater != c.shouldUpdateLater {
			t.Errorf("%s: Update trigger mismatch, expected %v, got %v", c.name, c.shouldUpdateLater, triggeredLater)
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
			name:            "Update to a specific version should update regardless of if latestVersion is available yet",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "0.56.0",
			shouldUpdate:    true,
		},
		{
			name:            "Update to specific version should not update if version matches",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "0.55.0",
			shouldUpdate:    false,
		},
		{
			name:            "Update to specific version should not update if current version is newer",
			daemonVersion:   "0.55.0",
			latestVersion:   nil,
			expectedVersion: "0.54.0",
			shouldUpdate:    false,
		},
		{
			name:            "Update to latest version should update if latest is newer",
			daemonVersion:   "0.55.0",
			latestVersion:   v.Must(v.NewSemver("0.56.0")),
			expectedVersion: "latest",
			shouldUpdate:    true,
		},
		{
			name:            "Update to latest version should not update if latest == current",
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
		m, _ := newManager(peer.NewRecorder(""), statemanager.New(tmpFile))
		m.update = &versionUpdateMock{latestVersion: c.latestVersion}
		targetVersionChan := make(chan string, 1)

		m.triggerUpdateFn = func(ctx context.Context, targetVersion string) error {
			targetVersionChan <- targetVersion
			return nil
		}

		m.currentVersion = c.daemonVersion
		m.Start(context.Background())
		m.SetVersion(c.expectedVersion)

		var updateTriggered bool
		select {
		case targetVersion := <-targetVersionChan:
			if c.expectedVersion == "latest" && targetVersion != c.latestVersion.String() {
				t.Errorf("%s: Update version mismatch, expected %v, got %v", c.name, c.latestVersion.String(), targetVersion)
			} else if c.expectedVersion != "latest" && targetVersion != c.expectedVersion {
				t.Errorf("%s: Update version mismatch, expected %v, got %v", c.name, c.expectedVersion, targetVersion)
			}
			updateTriggered = true
		case <-time.After(10 * time.Millisecond):
			updateTriggered = false
		}

		if updateTriggered != c.shouldUpdate {
			t.Errorf("%s: Update trigger mismatch, expected %v, got %v", c.name, c.shouldUpdate, updateTriggered)
		}
		m.Stop()
	}
}
