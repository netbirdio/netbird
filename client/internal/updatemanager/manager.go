package updatemanager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	v "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

const (
	latestVersion = "latest"
	// this version will be ignored
	developmentVersion = "development"
)

type UpdateInterface interface {
	StopWatch()
	SetDaemonVersion(newVersion string) bool
	SetOnUpdateListener(updateFn func())
	LatestVersion() *v.Version
	StartFetcher()
}

type UpdateState struct {
	PreUpdateVersion string
	TargetVersion    string
}

func (u UpdateState) Name() string {
	return "autoUpdate"
}

type Manager struct {
	statusRecorder *peer.Status
	stateManager   *statemanager.Manager

	lastTrigger    time.Time
	mgmUpdateChan  chan struct{}
	updateChannel  chan struct{}
	currentVersion string
	update         UpdateInterface
	wg             sync.WaitGroup

	cancel context.CancelFunc

	expectedVersion       *v.Version
	updateToLatestVersion bool

	// updateMutex protect update and expectedVersion fields
	updateMutex sync.Mutex
}

func NewManager(statusRecorder *peer.Status, stateManager *statemanager.Manager) *Manager {
	manager := &Manager{
		statusRecorder: statusRecorder,
		stateManager:   stateManager,
		mgmUpdateChan:  make(chan struct{}, 1),
		updateChannel:  make(chan struct{}, 1),
		currentVersion: version.NetbirdVersion(),
		update:         version.NewUpdate("nb/client"),
	}

	return manager
}

// CheckUpdateSuccess checks if the update was successful. It works without to start the update manager.
func (m *Manager) CheckUpdateSuccess(ctx context.Context) {
	inst := installer.New()
	if err := inst.CleanUpInstallerFile(); err != nil {
		log.Errorf("failed to clean up temporary installer file: %v", err)
	}
	m.updateStateManager(ctx)
	return
}

func (m *Manager) Start(ctx context.Context) {
	if m.cancel != nil {
		log.Errorf("Manager already started")
		return
	}

	m.update.SetDaemonVersion(m.currentVersion)
	m.update.SetOnUpdateListener(func() {
		select {
		case m.updateChannel <- struct{}{}:
		default:
		}
	})
	go m.update.StartFetcher()

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	m.wg.Add(1)
	go m.updateLoop(ctx)
}

func (m *Manager) SetVersion(expectedVersion string) {
	log.Infof("set expected agent version for upgrade: %s", expectedVersion)
	if m.cancel == nil {
		log.Errorf("Manager not started")
		return
	}

	m.updateMutex.Lock()
	defer m.updateMutex.Unlock()
	if expectedVersion == latestVersion {
		m.updateToLatestVersion = true
		m.expectedVersion = nil
	} else {
		expectedSemVer, err := v.NewVersion(expectedVersion)
		if err != nil {
			log.Errorf("Error parsing version: %v", err)
			return
		}
		if m.expectedVersion != nil && m.expectedVersion.Equal(expectedSemVer) {
			return
		}
		m.expectedVersion = expectedSemVer
		m.updateToLatestVersion = false
	}

	select {
	case m.mgmUpdateChan <- struct{}{}:
	default:
	}
}

func (m *Manager) Stop() {
	if m.cancel == nil {
		return
	}

	m.cancel()
	m.updateMutex.Lock()
	if m.update != nil {
		m.update.StopWatch()
		m.update = nil
	}
	m.updateMutex.Unlock()

	m.wg.Wait()
}

func (m *Manager) onContextCancel() {
	if m.cancel == nil {
		return
	}

	m.updateMutex.Lock()
	defer m.updateMutex.Unlock()
	if m.update != nil {
		m.update.StopWatch()
		m.update = nil
	}
}

func (m *Manager) updateLoop(ctx context.Context) {
	defer m.wg.Done()

	for {
		select {
		case <-ctx.Done():
			m.onContextCancel()
			return
		case <-m.mgmUpdateChan:
		case <-m.updateChannel:
			log.Infof("fetched new version info")
		}

		m.handleUpdate(ctx)
	}
}

func (m *Manager) handleUpdate(ctx context.Context) {
	var updateVersion *v.Version

	m.updateMutex.Lock()
	if m.update == nil {
		m.updateMutex.Unlock()
		return
	}

	expectedVersion := m.expectedVersion
	useLatest := m.updateToLatestVersion
	curLatestVersion := m.update.LatestVersion()
	m.updateMutex.Unlock()

	switch {
	// Resolve "latest" to actual version
	case useLatest:
		if curLatestVersion == nil {
			log.Tracef("latest version not fetched yet")
			return
		}
		updateVersion = curLatestVersion
	// Update to specific version
	case expectedVersion != nil:
		updateVersion = expectedVersion
	default:
		log.Debugf("no expected version information set")
		return
	}

	log.Debugf("checking update option, current version: %s, target version: %s", m.currentVersion, updateVersion)
	if !m.shouldUpdate(updateVersion) {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	m.lastTrigger = time.Now()
	log.Infof("Auto-update triggered, current version: %s, target version: %s", m.currentVersion, updateVersion)
	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_INFO,
		cProto.SystemEvent_SYSTEM,
		"Automatically updating client",
		"Your client version is older than auto-update version set in Management, updating client now.",
		nil,
	)

	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_INFO,
		cProto.SystemEvent_SYSTEM,
		"",
		"",
		map[string]string{"progress_window": "show"},
	)

	updateState := UpdateState{
		PreUpdateVersion: m.currentVersion,
		TargetVersion:    updateVersion.String(),
	}

	if err := m.stateManager.UpdateState(updateState); err != nil {
		log.Warnf("failed to update state: %v", err)
	} else {
		if err = m.stateManager.PersistState(ctx); err != nil {
			log.Warnf("failed to persist state: %v", err)
		}
	}

	if err := m.triggerUpdate(ctx, updateVersion.String()); err != nil {
		log.Errorf("Error triggering auto-update: %v", err)
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_ERROR,
			cProto.SystemEvent_SYSTEM,
			"Auto-update failed",
			fmt.Sprintf("Auto-update failed: %v", err),
			nil,
		)
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_INFO,
			cProto.SystemEvent_SYSTEM,
			"",
			"",
			map[string]string{"progress_window": "hide"},
		)
	}
}

func (m *Manager) updateStateManager(ctx context.Context) {
	stateType := &UpdateState{}

	m.stateManager.RegisterState(stateType)
	if err := m.stateManager.LoadState(stateType); err != nil {
		log.Errorf("failed to load state: %v", err)
		return
	}
	state := m.stateManager.GetState(stateType)
	if state == nil {
		return
	}

	updateState, ok := state.(*UpdateState)
	if !ok {
		log.Errorf("failed to cast state to UpdateState")
		return
	}
	log.Debugf("auto-update state loaded, %v", *updateState)
	if updateState.TargetVersion == m.currentVersion {
		log.Infof("published notification event")
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_INFO,
			cProto.SystemEvent_SYSTEM,
			"Auto-update completed",
			fmt.Sprintf("Your NetBird Client was auto-updated to version %s", m.currentVersion),
			nil,
		)
	}
	if err := m.stateManager.DeleteState(updateState); err != nil {
		log.Errorf("failed to delete state: %v", err)
	} else if err = m.stateManager.PersistState(ctx); err != nil {
		log.Errorf("failed to persist state: %v", err)
	}
}

func (m *Manager) shouldUpdate(updateVersion *v.Version) bool {
	if m.currentVersion == developmentVersion {
		log.Debugf("skipping auto-update, running development version")
		return false
	}
	currentVersion, err := v.NewVersion(m.currentVersion)
	if err != nil {
		log.Errorf("error checking for update, error parsing version `%s`: %v", m.currentVersion, err)
		return false
	}
	if currentVersion.GreaterThanOrEqual(updateVersion) {
		log.Infof("current version (%s) is equal to or higher than auto-update version (%s)", m.currentVersion, updateVersion)
		return false
	}

	if time.Since(m.lastTrigger) < 5*time.Minute {
		log.Debugf("skipping auto-update, last update was %s ago", time.Since(m.lastTrigger))
		return false
	}

	return true
}

func downloadFileToTemporaryDir(ctx context.Context, tempDir, fileURL string) (string, error) {
	// Clean up temp directory on error
	var success bool
	defer func() {
		if !success {
			if err := os.RemoveAll(tempDir); err != nil {
				log.Errorf("error cleaning up temporary directory: %v", err)
			}
		}
	}()

	fileNameParts := strings.Split(fileURL, "/")
	out, err := os.Create(filepath.Join(tempDir, fileNameParts[len(fileNameParts)-1]))
	if err != nil {
		return "", fmt.Errorf("error creating temporary file: %w", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Errorf("error closing temporary file: %v", err)
		}
	}()

	log.Debugf("downloading update file from %s", fileURL)
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

	if resp.StatusCode != http.StatusOK {
		log.Errorf("error downloading update file, received status code: %d", resp.StatusCode)
		return "", fmt.Errorf("error downloading file, received status code: %d", resp.StatusCode)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}

	log.Infof("downloaded update file to %s", out.Name())

	success = true // Mark success to prevent cleanup
	return out.Name(), nil
}
