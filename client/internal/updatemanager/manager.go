package updatemanager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	v "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

const (
	latestVersion = "latest"
)

type UpdateInterface interface {
	StopWatch()
	SetDaemonVersion(newVersion string) bool
	SetOnUpdateListener(updateFn func())
	LatestVersion() *v.Version
	StartFetcher()
}

type UpdateManager struct {
	lastTrigger    time.Time
	statusRecorder *peer.Status
	mgmUpdateChan  chan struct{}
	updateChannel  chan struct{}
	wg             sync.WaitGroup
	currentVersion string
	updateFunc     func(ctx context.Context, targetVersion string) error

	cancel context.CancelFunc
	update UpdateInterface

	expectedVersion       *v.Version
	updateToLatestVersion bool
	expectedVersionMutex  sync.Mutex
}

func NewUpdateManager(statusRecorder *peer.Status) *UpdateManager {
	manager := &UpdateManager{
		statusRecorder: statusRecorder,
		mgmUpdateChan:  make(chan struct{}, 1),
		updateChannel:  make(chan struct{}, 1),
		currentVersion: version.NetbirdVersion(),
		updateFunc:     triggerUpdate,
		update:         version.NewUpdate("nb/client"),
	}
	return manager
}

func (u *UpdateManager) WithCustomVersionUpdate(versionUpdate UpdateInterface) *UpdateManager {
	u.update = versionUpdate
	return u
}

func (u *UpdateManager) Start(ctx context.Context) {
	if u.cancel != nil {
		log.Errorf("UpdateManager already started")
		return
	}

	go u.update.StartFetcher()
	u.update.SetDaemonVersion(u.currentVersion)
	u.update.SetOnUpdateListener(func() {
		select {
		case u.updateChannel <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(ctx)
	u.cancel = cancel

	u.wg.Add(1)
	go u.updateLoop(ctx)
}

func (u *UpdateManager) SetVersion(expectedVersion string) {
	if u.cancel == nil {
		log.Errorf("UpdateManager not started")
		return
	}

	u.expectedVersionMutex.Lock()
	defer u.expectedVersionMutex.Unlock()
	if expectedVersion == latestVersion {
		u.updateToLatestVersion = true
		u.expectedVersion = nil
	} else {
		expectedSemVer, err := v.NewVersion(expectedVersion)
		if err != nil {
			log.Errorf("Error parsing version: %v", err)
			return
		}
		if u.expectedVersion.Equal(expectedSemVer) {
			return
		}
		u.expectedVersion = expectedSemVer
		u.updateToLatestVersion = false
	}

	select {
	case u.mgmUpdateChan <- struct{}{}:
	default:
	}
}

func (u *UpdateManager) Stop() {
	if u.cancel == nil {
		return
	}

	u.cancel()
	if u.update != nil {
		u.update.StopWatch()
		u.update = nil
	}

	u.wg.Wait()
}

func (u *UpdateManager) updateLoop(ctx context.Context) {
	defer u.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-u.mgmUpdateChan:
		case <-u.updateChannel:
		}

		u.handleUpdate(ctx)
	}
}

func (u *UpdateManager) handleUpdate(ctx context.Context) {
	var updateVersion *v.Version

	u.expectedVersionMutex.Lock()
	expectedVersion := u.expectedVersion
	useLatest := u.updateToLatestVersion
	curLatestVersion := u.update.LatestVersion()
	u.expectedVersionMutex.Unlock()

	switch {
	// Resolve "latest" to actual version
	case useLatest:
		if curLatestVersion == nil {
			log.Tracef("Latest version not fetched yet")
			return
		}
		updateVersion = curLatestVersion
	// Update to specific version
	case u.expectedVersion != nil:
		updateVersion = expectedVersion
	default:
		log.Debugf("No expected version information set")
		return
	}

	if !u.shouldUpdate(updateVersion) {
		return
	}

	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Minute))
	defer cancel()

	u.lastTrigger = time.Now()
	log.Debugf("Auto-update triggered, current version: %s, target version: %s", u.currentVersion, updateVersion)
	u.statusRecorder.PublishEvent(
		cProto.SystemEvent_INFO,
		cProto.SystemEvent_SYSTEM,
		"Automatically updating client",
		"Your client version is older than auto-update version set in Management, updating client now.",
		nil,
	)

	err := u.updateFunc(ctx, updateVersion.String())
	if err != nil {
		log.Errorf("Error triggering auto-update: %v", err)
	}
}

func (u *UpdateManager) shouldUpdate(updateVersion *v.Version) bool {
	currentVersion, err := v.NewVersion(u.currentVersion)
	if err != nil {
		log.Errorf("Error checking for update, error parsing version `%s`: %v", u.currentVersion, err)
		return false
	}
	if currentVersion.GreaterThanOrEqual(updateVersion) {
		log.Debugf("Current version (%s) is equal to or higher than auto-update version (%s)", u.currentVersion, updateVersion)
		return false
	}

	if time.Since(u.lastTrigger) < 5*time.Minute {
		log.Tracef("No need to update")
		return false
	}

	return true
}

func downloadFileToTemporaryDir(ctx context.Context, fileURL string) (string, error) { //nolint:unused
	tempDir, err := os.MkdirTemp("", "netbird-installer-*")
	if err != nil {
		return "", fmt.Errorf("error creating temporary directory: %w", err)
	}
	fileNameParts := strings.Split(fileURL, "/")
	out, err := os.Create(filepath.Join(tempDir, fileNameParts[len(fileNameParts)-1]))
	if err != nil {
		return "", fmt.Errorf("error creating temporary file: %w", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Errorf("Error closing temporary file: %v", err)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating file download request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("Error closing response body: %v", err)
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}

	log.Tracef("Downloaded update file to %s", out.Name())

	return out.Name(), nil
}

func urlWithVersionArch(url, version string) string { //nolint:unused
	url = strings.ReplaceAll(url, "%version", version)
	url = strings.ReplaceAll(url, "%arch", runtime.GOARCH)
	return url
}
