package updater

import (
	"context"
	"path"
	"sync/atomic"
	"testing"
	"time"

	v "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

func newNotificationTestManager(t *testing.T, disabled *atomic.Bool) (*Manager, *peer.EventSubscription) {
	t.Helper()

	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	t.Cleanup(func() { recorder.UnsubscribeFromEvents(sub) })

	m := NewManager(context.Background(), recorder, statemanager.New(path.Join(t.TempDir(), "state.json")))
	m.update = &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m.currentVersion = "1.0.0"
	m.autoUpdateSupported = func() bool { return true }
	m.SetNotificationsDisabled(disabled.Load)
	m.Start(context.Background())
	t.Cleanup(m.Stop)
	return m, sub
}

func TestNotificationsDisabled_DownloadOnlyPublishesNothing(t *testing.T) {
	var disabled atomic.Bool
	disabled.Store(true)
	m, sub := newNotificationTestManager(t, &disabled)

	m.SetDownloadOnly()
	ver, _ := waitForUpdateEvent(sub, 300*time.Millisecond)
	assert.Empty(t, ver, "a fetched newer version must not be announced while notifications are disabled")

	m.NotifyUI()
	ver, _ = waitForUpdateEvent(sub, 300*time.Millisecond)
	assert.Empty(t, ver, "NotifyUI replays the last announcement and must honour the policy too")
}

func TestNotificationsDisabled_ManagedModeKeepsPendingVersion(t *testing.T) {
	var disabled atomic.Bool
	disabled.Store(true)
	m, sub := newNotificationTestManager(t, &disabled)

	m.SetVersion("1.0.1", false)

	// handleUpdate records the pending version before it tries to announce it,
	// so once it is set the announcement has been attempted or is about to be.
	pendingVersion := func() *v.Version {
		m.updateMutex.Lock()
		defer m.updateMutex.Unlock()
		return m.pendingVersion
	}
	require.Eventually(t, func() bool { return pendingVersion() != nil }, 5*time.Second, 10*time.Millisecond,
		"suppressing the announcement must not drop the pending install")
	assert.Equal(t, "1.0.1", pendingVersion().String())

	ver, _ := waitForUpdateEvent(sub, 300*time.Millisecond)
	assert.Empty(t, ver, "the enforced prompt must be suppressed too")
}

func TestNotificationsDisabled_ReEnabledAtRuntime(t *testing.T) {
	var disabled atomic.Bool
	disabled.Store(true)
	m, sub := newNotificationTestManager(t, &disabled)

	m.SetDownloadOnly()
	ver, _ := waitForUpdateEvent(sub, 300*time.Millisecond)
	require.Empty(t, ver)

	disabled.Store(false)
	m.NotifyUI()
	ver, _ = waitForUpdateEvent(sub, 500*time.Millisecond)
	assert.Equal(t, "1.0.1", ver, "clearing the policy must let the next NotifyUI announce the version")
}

func TestNotificationsEnabledByDefault(t *testing.T) {
	recorder := peer.NewRecorder("")
	sub := recorder.SubscribeToEvents()
	defer recorder.UnsubscribeFromEvents(sub)

	m := NewManager(context.Background(), recorder, statemanager.New(path.Join(t.TempDir(), "state.json")))
	m.update = &versionUpdateMock{latestVersion: v.Must(v.NewSemver("1.0.1"))}
	m.currentVersion = "1.0.0"
	m.Start(context.Background())
	defer m.Stop()

	m.SetDownloadOnly()
	ver, _ := waitForUpdateEvent(sub, 500*time.Millisecond)
	assert.Equal(t, "1.0.1", ver, "a manager without a predicate keeps announcing")
}
