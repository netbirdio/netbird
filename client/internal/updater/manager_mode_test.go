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
	m := NewManager(recorder, statemanager.New(tmpFile))
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
	m := NewManager(recorder, statemanager.New(tmpFile))
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
