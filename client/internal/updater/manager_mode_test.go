package updater

import (
	"context"
	"path"
	"testing"
	"time"

	v "github.com/hashicorp/go-version"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

func Test_UndecidedMode_SuppressesNotification(t *testing.T) {
	tmpFile := path.Join(t.TempDir(), "update-test-undecided.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	mockUpdate := &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m := NewManager(context.Background(), recorder, statemanager.New(tmpFile))
	m.update = mockUpdate
	m.currentVersion = "1.0.0"
	m.Start(context.Background())
	defer m.Stop()

	mockUpdate.onUpdate()
	if ver, _ := waitForUpdateEvent(sub, 300*time.Millisecond); ver != "" {
		t.Fatalf("undecided mode must not publish, got %q", ver)
	}

	m.NotifyUI()
	if ver, _ := waitForUpdateEvent(sub, 300*time.Millisecond); ver != "" {
		t.Fatalf("NotifyUI in undecided mode must not publish, got %q", ver)
	}

	m.SetDownloadOnly()
	ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond)
	if ver != "1.0.1" {
		t.Fatalf("expected download-only event for 1.0.1, got %q", ver)
	}
	if enforced {
		t.Error("download-only event must not carry enforced metadata")
	}
}

func Test_ResetMode_ReturnsToUndecided(t *testing.T) {
	tmpFile := path.Join(t.TempDir(), "update-test-reset.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	mockUpdate := &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m := NewManager(context.Background(), recorder, statemanager.New(tmpFile))
	m.update = mockUpdate
	m.currentVersion = "1.0.0"
	m.autoUpdateSupported = func() bool { return true }
	m.Start(context.Background())
	defer m.Stop()

	m.SetVersion("1.0.1", false)
	ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond)
	if ver != "1.0.1" || !enforced {
		t.Fatalf("expected enforced event for 1.0.1, got %q enforced=%v", ver, enforced)
	}

	m.ResetMode()

	mockUpdate.onUpdate()
	if ver, _ := waitForUpdateEvent(sub, 300*time.Millisecond); ver != "" {
		t.Fatalf("reset mode must not publish on fetch, got %q", ver)
	}

	m.NotifyUI()
	if ver, _ := waitForUpdateEvent(sub, 300*time.Millisecond); ver != "" {
		t.Fatalf("NotifyUI after reset must not publish, got %q", ver)
	}

	if err := m.Install(context.Background()); err == nil {
		t.Fatal("Install after reset must fail without a pending version")
	}

	m.SetVersion("1.0.1", false)
	ver, enforced = waitForUpdateEvent(sub, 500*time.Millisecond)
	if ver != "1.0.1" || !enforced {
		t.Fatalf("expected enforced event again after reset, got %q enforced=%v", ver, enforced)
	}
}

func Test_SetDownloadOnly_ClearsPendingVersion(t *testing.T) {
	tmpFile := path.Join(t.TempDir(), "update-test-pending.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(context.Background(), recorder, statemanager.New(tmpFile))
	m.update = &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m.currentVersion = "1.0.0"
	m.autoUpdateSupported = func() bool { return true }
	m.Start(context.Background())
	defer m.Stop()

	m.SetVersion("1.0.1", false)
	if ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond); ver != "1.0.1" || !enforced {
		t.Fatalf("expected enforced event for 1.0.1, got %q enforced=%v", ver, enforced)
	}

	m.SetDownloadOnly()
	if ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond); ver != "1.0.1" || enforced {
		t.Fatalf("expected download-only event for 1.0.1, got %q enforced=%v", ver, enforced)
	}

	if err := m.Install(context.Background()); err == nil {
		t.Fatal("Install in download-only mode must not install the staged managed version")
	}
}

func Test_ResetMode_SilencesStaleForceDirective(t *testing.T) {
	tmpFile := path.Join(t.TempDir(), "update-test-force-reset.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	mockUpdate := &versionUpdateMock{}
	m := NewManager(context.Background(), recorder, statemanager.New(tmpFile))
	m.update = mockUpdate
	m.currentVersion = "1.0.0"
	m.autoUpdateSupported = func() bool { return true }
	m.Start(context.Background())
	defer m.Stop()

	// Management enforces "latest" before the fetcher has reported any version,
	// so nothing can be installed while the engine is still up.
	m.SetVersion(latestVersion, true)
	if event := waitForAnyEvent(sub, 300*time.Millisecond); event != nil {
		t.Fatalf("no event expected before the latest version is known, got %v", event)
	}

	// The engine stop resets the mode. A release published afterwards must not
	// trigger the stale forced install or any notification.
	m.ResetMode()
	mockUpdate.setLatestVersion(v.Must(v.NewSemver("1.0.1")))
	mockUpdate.onUpdate()
	if event := waitForAnyEvent(sub, 300*time.Millisecond); event != nil {
		t.Fatalf("stale force directive must stay silent after reset, got %v", event)
	}

	m.SetVersion("1.0.1", false)
	ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond)
	if ver != "1.0.1" || !enforced {
		t.Fatalf("expected enforced event after a fresh directive, got %q enforced=%v", ver, enforced)
	}
}

func Test_SetVersion_MalformedFallsBackToDownloadOnly(t *testing.T) {
	tmpFile := path.Join(t.TempDir(), "update-test-malformed.json")
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(context.Background(), recorder, statemanager.New(tmpFile))
	m.update = &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m.currentVersion = "1.0.0"
	m.autoUpdateSupported = func() bool { return true }
	m.Start(context.Background())
	defer m.Stop()

	m.SetVersion("not-a-version", false)
	ver, enforced := waitForUpdateEvent(sub, 500*time.Millisecond)
	if ver != "1.0.1" {
		t.Fatalf("expected download-only event for 1.0.1 after malformed version, got %q", ver)
	}
	if enforced {
		t.Error("malformed version fallback must not carry enforced metadata")
	}
}

func Test_SetVersion_ForceChangeAppliesWithSameVersion(t *testing.T) {
	m := NewManager(context.Background(), peer.NewRecorder(""), statemanager.New(path.Join(t.TempDir(), "update-test-force-change.json")))
	m.update = &versionUpdateMock{}
	m.autoUpdateSupported = func() bool { return true }

	m.SetVersion("1.0.1", false)
	m.SetVersion("1.0.1", true)

	m.updateMutex.Lock()
	defer m.updateMutex.Unlock()
	if !m.forceUpdate {
		t.Fatal("enabling force update without a version change must take effect")
	}
	if m.expectedVersion == nil || m.expectedVersion.String() != "1.0.1" {
		t.Fatalf("expected version 1.0.1 to stay set, got %v", m.expectedVersion)
	}
}

func Test_SetVersion_RepeatedDirectiveKeepsMode(t *testing.T) {
	m := NewManager(context.Background(), peer.NewRecorder(""), statemanager.New(path.Join(t.TempDir(), "update-test-repeat.json")))
	m.update = &versionUpdateMock{}
	m.autoUpdateSupported = func() bool { return true }

	for _, expected := range []string{"1.0.1", latestVersion} {
		m.SetVersion(expected, false)
		m.updateMutex.Lock()
		gen := m.modeGen
		m.updateMutex.Unlock()

		m.SetVersion(expected, false)
		m.updateMutex.Lock()
		repeatedGen := m.modeGen
		m.updateMutex.Unlock()

		if repeatedGen != gen {
			t.Errorf("repeating the %q directive must not reset the mode", expected)
		}
	}
}

func managerStarted(m *Manager) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cancel != nil
}

func Test_SetVersion_ForceStartsLoopWithoutSubscriber(t *testing.T) {
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(context.Background(), recorder, statemanager.New(path.Join(t.TempDir(), "update-test-force-start.json")))
	m.update = &versionUpdateMock{}
	// Already on the forced version, so the started loop has nothing to install.
	m.currentVersion = "1.0.1"
	m.autoUpdateSupported = func() bool { return true }
	defer m.Stop()

	// No UI has subscribed to daemon events, so nothing else calls Start.
	m.SetVersion("1.0.1", true)

	if !managerStarted(m) {
		t.Fatal("a forced directive must start the update loop without a UI subscriber")
	}
	if event := waitForAnyEvent(sub, 300*time.Millisecond); event != nil {
		t.Fatalf("no install expected when already on the forced version, got %v", event)
	}
}

func Test_SetVersion_EnforcedWithoutForceWaitsForSubscriber(t *testing.T) {
	m := NewManager(context.Background(), peer.NewRecorder(""), statemanager.New(path.Join(t.TempDir(), "update-test-enforced-wait.json")))
	m.update = &versionUpdateMock{}
	m.currentVersion = "1.0.0"
	m.autoUpdateSupported = func() bool { return true }
	defer m.Stop()

	m.SetVersion("1.0.1", false)

	if managerStarted(m) {
		t.Fatal("an enforced directive without force needs the UI prompt, so it must not start the loop")
	}
}
