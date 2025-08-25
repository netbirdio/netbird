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

type UpdateManager struct {
	lastTrigger    time.Time
	statusRecorder *peer.Status
	mgmUpdateChan  chan struct{}
	updateChannel  chan struct{}
	wg             sync.WaitGroup

	cancel context.CancelFunc
	update *version.Update

	expectedVersion      string
	expectedVersionMutex sync.Mutex
}

func NewUpdateManager(statusRecorder *peer.Status) *UpdateManager {
	manager := &UpdateManager{
		statusRecorder: statusRecorder,
		mgmUpdateChan:  make(chan struct{}, 1),
		updateChannel:  make(chan struct{}, 1),
	}
	return manager
}

func (u *UpdateManager) Start(ctx context.Context) {
	if u.cancel != nil {
		log.Errorf("UpdateManager already started")
		return
	}

	u.update = version.NewUpdate("nb/client")
	u.update.SetDaemonVersion(version.NetbirdVersion())
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

func (u *UpdateManager) SetVersion(v string) {
	if u.cancel == nil {
		log.Errorf("UpdateManager not started")
		return
	}

	u.expectedVersionMutex.Lock()
	defer u.expectedVersionMutex.Unlock()
	if u.expectedVersion == v {
		return
	}

	u.expectedVersion = v

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
	u.expectedVersionMutex.Unlock()

	// Resolve "latest" to actual version
	if expectedVersion == latestVersion {
		if !u.isVersionAvailable() {
			log.Tracef("Latest version not fetched yet")
			return
		}
		updateVersion = u.update.LatestVersion()
	} else {
		var err error
		updateVersion, err = v.NewSemver(expectedVersion)
		if err != nil {
			log.Errorf("Failed to parse latest version: %v", err)
			return
		}
	}

	if !u.shouldUpdate(updateVersion) {
		return
	}

	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Minute))
	defer cancel()

	u.lastTrigger = time.Now()
	log.Debugf("Auto-update triggered, current version: %s, target version: %s", version.NetbirdVersion(), updateVersion)
	u.statusRecorder.PublishEvent(
		cProto.SystemEvent_INFO,
		cProto.SystemEvent_SYSTEM,
		"Automatically updating client",
		"Your client version is older than auto-update version set in Management, updating client now.",
		nil,
	)

	err := u.triggerUpdate(ctx, updateVersion.String())
	if err != nil {
		log.Errorf("Error triggering auto-update: %v", err)
	}
}

func (u *UpdateManager) shouldUpdate(updateVersion *v.Version) bool {
	currentVersionString := version.NetbirdVersion()
	currentVersion, err := v.NewVersion(currentVersionString)
	if err != nil {
		log.Errorf("Error checking for update, error parsing version `%s`: %v", currentVersionString, err)
		return false
	}
	if currentVersion.GreaterThanOrEqual(updateVersion) {
		log.Debugf("Current version (%s) is equal to or higher than auto-update version (%s)", currentVersionString, updateVersion)
		return false
	}

	if time.Since(u.lastTrigger) < 5*time.Minute {
		log.Tracef("No need to update")
		return false
	}

	return true
}

func (u *UpdateManager) isVersionAvailable() bool {
	if u.update.LatestVersion() == nil {
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
