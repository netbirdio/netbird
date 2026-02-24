//go:build !windows && !darwin

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

// On Linux, only Mode 1 (downloadOnly) is supported.
// SetVersion is a no-op because auto-update installation is not supported.

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
			name:                 "Should only notify once due to time between triggers being < 5 Minutes",
			daemonVersion:        "1.0.0",
			initialLatestVersion: v.Must(v.NewSemver("1.0.1")),
			latestVersion:        v.Must(v.NewSemver("1.0.2")),
			shouldUpdateInit:     true,
			shouldUpdateLater:    false,
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

		m := NewManager(recorder, statemanager.New(tmpFile))
		m.update = mockUpdate
		m.currentVersion = c.daemonVersion
		m.Start(context.Background())
		m.SetDownloadOnly()

		ver, enforced := waitForUpdateEvent(sub, 10*time.Millisecond)
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

		mockUpdate.latestVersion = c.latestVersion
		mockUpdate.onUpdate()

		ver, enforced = waitForUpdateEvent(sub, 10*time.Millisecond)
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

func Test_SetVersion_NoOp_Linux(t *testing.T) {
	// On Linux, SetVersion should be a no-op — no events fired
	tmpFile := path.Join(t.TempDir(), "update-test-noop.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(recorder, statemanager.New(tmpFile))
	m.update = &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m.currentVersion = "1.0.0"
	m.Start(context.Background())
	m.SetVersion("1.0.1", false)

	ver, _ := waitForUpdateEvent(sub, 10*time.Millisecond)
	if ver != "" {
		t.Errorf("SetVersion should be a no-op on Linux, but got event with version %s", ver)
	}

	m.Stop()
}
