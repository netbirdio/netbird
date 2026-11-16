package updater

import (
	"strconv"
	"sync"
	"time"

	v "github.com/hashicorp/go-version"

	"github.com/netbirdio/netbird/client/internal/peer"
	cProto "github.com/netbirdio/netbird/client/proto"
)

type versionUpdateMock struct {
	latestVersion *v.Version
	onUpdate      func()
	mu            sync.Mutex
}

func (m *versionUpdateMock) StopWatch() {}

func (m *versionUpdateMock) SetDaemonVersion(newVersion string) bool {
	return false
}

func (m *versionUpdateMock) SetOnUpdateListener(updateFn func()) {
	m.onUpdate = updateFn
}

func (m *versionUpdateMock) LatestVersion() *v.Version {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.latestVersion
}

func (m *versionUpdateMock) StartFetcher() {}

func (m *versionUpdateMock) setLatestVersion(version *v.Version) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latestVersion = version
}

// waitForUpdateEvent waits for a new_version_available event, returns the version string or "" on timeout.
func waitForUpdateEvent(sub *peer.EventSubscription, timeout time.Duration) (version string, enforced bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event, ok := <-sub.Events():
			if !ok {
				return "", false
			}
			if val, ok := event.Metadata["new_version_available"]; ok {
				enforced := false
				if raw, ok := event.Metadata["enforced"]; ok {
					if parsed, err := strconv.ParseBool(raw); err == nil {
						enforced = parsed
					}
				}
				return val, enforced
			}
		case <-timer.C:
			return "", false
		}
	}
}

// waitForAnyEvent returns the first published event of any kind, or nil on timeout.
// Unlike waitForUpdateEvent it also catches the install-progress events, so a test
// can assert that a forced install never started.
func waitForAnyEvent(sub *peer.EventSubscription, timeout time.Duration) *cProto.SystemEvent {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case event, ok := <-sub.Events():
		if !ok {
			return nil
		}
		return event
	case <-timer.C:
		return nil
	}
}
