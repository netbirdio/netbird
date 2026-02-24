package updatemanager

import (
	"time"

	v "github.com/hashicorp/go-version"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type versionUpdateMock struct {
	latestVersion *v.Version
	onUpdate      func()
}

func (m versionUpdateMock) StopWatch() {}

func (m versionUpdateMock) SetDaemonVersion(newVersion string) bool {
	return false
}

func (m *versionUpdateMock) SetOnUpdateListener(updateFn func()) {
	m.onUpdate = updateFn
}

func (m versionUpdateMock) LatestVersion() *v.Version {
	return m.latestVersion
}

func (m versionUpdateMock) StartFetcher() {}

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
				_, enforced := event.Metadata["enforced"]
				return val, enforced
			}
		case <-timer.C:
			return "", false
		}
	}
}
