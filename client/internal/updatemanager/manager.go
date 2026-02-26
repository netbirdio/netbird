package updatemanager

import (
	"context"
	"errors"
	"fmt"
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

var errNoUpdateState = errors.New("no update state found")

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

	downloadOnly bool // true when no enforcement from management; notifies UI to download latest
	forceUpdate  bool // true when management sets AlwaysUpdate; skips UI interaction and installs directly

	lastTrigger    time.Time
	mgmUpdateChan  chan struct{}
	updateChannel  chan struct{}
	currentVersion string
	update         UpdateInterface
	wg             sync.WaitGroup

	cancel context.CancelFunc

	expectedVersion       *v.Version
	updateToLatestVersion bool

	pendingVersion *v.Version

	// updateMutex protects update, expectedVersion, updateToLatestVersion,
	// downloadOnly, forceUpdate, pendingVersion, and lastTrigger fields
	updateMutex sync.Mutex

	// installMutex and installing guard against concurrent installation attempts
	installMutex sync.Mutex
	installing   bool

	// protect to start the service multiple times
	mu sync.Mutex
}

func NewManager(statusRecorder *peer.Status, stateManager *statemanager.Manager) *Manager {
	manager := &Manager{
		statusRecorder: statusRecorder,
		stateManager:   stateManager,
		mgmUpdateChan:  make(chan struct{}, 1),
		updateChannel:  make(chan struct{}, 1),
		currentVersion: version.NetbirdVersion(),
		update:         version.NewUpdate("nb/client"),
		downloadOnly:   true,
	}

	stateManager.RegisterState(&UpdateState{})

	return manager
}

// CheckUpdateSuccess checks if the update was successful and send a notification.
// It works without to start the update manager.
func (m *Manager) CheckUpdateSuccess(ctx context.Context) {
	reason := m.lastResultErrReason()
	if reason != "" {
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_ERROR,
			cProto.SystemEvent_SYSTEM,
			"Auto-update failed",
			fmt.Sprintf("Auto-update failed: %s", reason),
			nil,
		)
	}

	updateState, err := m.loadAndDeleteUpdateState(ctx)
	if err != nil {
		if errors.Is(err, errNoUpdateState) {
			return
		}
		log.Errorf("failed to load update state: %v", err)
		return
	}

	log.Debugf("auto-update state loaded, %v", *updateState)

	if updateState.TargetVersion == m.currentVersion {
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_INFO,
			cProto.SystemEvent_SYSTEM,
			"Auto-update completed",
			fmt.Sprintf("Your NetBird Client was auto-updated to version %s", m.currentVersion),
			nil,
		)
		return
	}
}

func (m *Manager) Start(ctx context.Context) {
	log.Infof("starting update manager")
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
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
	go func() {
		defer m.wg.Done()
		m.updateLoop(ctx)
	}()
}

func (m *Manager) SetDownloadOnly() {
	m.updateMutex.Lock()
	m.downloadOnly = true
	m.forceUpdate = false
	m.expectedVersion = nil
	m.updateToLatestVersion = false
	m.updateMutex.Unlock()

	select {
	case m.mgmUpdateChan <- struct{}{}:
	default:
	}
}

func (m *Manager) SetVersion(expectedVersion string, forceUpdate bool) {
	log.Infof("set expected agent version for upgrade: %s", expectedVersion)

	if !isAutoUpdateSupported() {
		log.Warnf("auto-update not supported on this platform")
		return
	}

	m.updateMutex.Lock()
	defer m.updateMutex.Unlock()

	if expectedVersion == "" {
		log.Errorf("empty expected version provided")
		m.expectedVersion = nil
		m.updateToLatestVersion = false
		m.downloadOnly = true
		return
	}

	m.downloadOnly = false
	m.forceUpdate = forceUpdate

	if expectedVersion == latestVersion {
		m.updateToLatestVersion = true
		m.expectedVersion = nil
	} else {
		expectedSemVer, err := v.NewVersion(expectedVersion)
		if err != nil {
			log.Errorf("error parsing version: %v", err)
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

// Install triggers the installation of the pending version. It is called when the user clicks the install button in the UI.
func (m *Manager) Install(ctx context.Context) error {
	if !isAutoUpdateSupported() {
		return fmt.Errorf("auto-update not supported on this platform")
	}

	m.updateMutex.Lock()
	pending := m.pendingVersion
	m.updateMutex.Unlock()

	if pending == nil {
		return fmt.Errorf("no pending version to install")
	}

	return m.tryInstall(ctx, pending)
}

// tryInstall ensures only one installation runs at a time. Concurrent callers
// receive an error immediately rather than queuing behind a running install.
func (m *Manager) tryInstall(ctx context.Context, targetVersion *v.Version) error {
	m.installMutex.Lock()
	if m.installing {
		m.installMutex.Unlock()
		return fmt.Errorf("installation already in progress")
	}
	m.installing = true
	m.installMutex.Unlock()

	defer func() {
		m.installMutex.Lock()
		m.installing = false
		m.installMutex.Unlock()
	}()

	return m.install(ctx, targetVersion)
}

// NotifyUI re-publishes the current update state to a newly connected UI client.
// Only needed for download-only mode where the latest version is already cached
// and won't be re-fetched on reconnect. In enforced modes, mgm will re-send the
// policy on the next sync which triggers the notification naturally.
func (m *Manager) NotifyUI() {
	m.updateMutex.Lock()
	if !m.downloadOnly || m.update == nil {
		m.updateMutex.Unlock()
		return
	}
	latestVersion := m.update.LatestVersion()
	m.updateMutex.Unlock()

	if latestVersion == nil {
		return
	}
	currentVersion, err := v.NewVersion(m.currentVersion)
	if err != nil || currentVersion.GreaterThanOrEqual(latestVersion) {
		return
	}

	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_INFO,
		cProto.SystemEvent_SYSTEM,
		"New version available",
		"",
		map[string]string{"new_version_available": latestVersion.String()},
	)
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

	downloadOnly := m.downloadOnly
	forceUpdate := m.forceUpdate
	curLatestVersion := m.update.LatestVersion()

	switch {
	// Download-only mode or resolve "latest" to actual version
	case downloadOnly, m.updateToLatestVersion:
		if curLatestVersion == nil {
			log.Tracef("latest version not fetched yet")
			m.updateMutex.Unlock()
			return
		}
		updateVersion = curLatestVersion
	// Install to specific version
	case m.expectedVersion != nil:
		updateVersion = m.expectedVersion
	default:
		log.Debugf("no expected version information set")
		m.updateMutex.Unlock()
		return
	}

	log.Debugf("checking update option, current version: %s, target version: %s", m.currentVersion, updateVersion)
	if !m.shouldUpdate(updateVersion, forceUpdate) {
		m.updateMutex.Unlock()
		return
	}

	m.lastTrigger = time.Now()
	log.Infof("new version available: %s", updateVersion)

	if !downloadOnly && !forceUpdate {
		m.pendingVersion = updateVersion
	}
	m.updateMutex.Unlock()

	if downloadOnly {
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_INFO,
			cProto.SystemEvent_SYSTEM,
			"New version available",
			"",
			map[string]string{"new_version_available": updateVersion.String()},
		)
		return
	}

	if forceUpdate {
		if err := m.tryInstall(ctx, updateVersion); err != nil {
			log.Errorf("force update failed: %v", err)
		}
		return
	}

	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_INFO,
		cProto.SystemEvent_SYSTEM,
		"New version available",
		"",
		map[string]string{"new_version_available": updateVersion.String(), "enforced": "true"},
	)
}

func (m *Manager) install(ctx context.Context, pendingVersion *v.Version) error {
	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_CRITICAL,
		cProto.SystemEvent_SYSTEM,
		"Updating client",
		"Installing update now.",
		nil,
	)
	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_CRITICAL,
		cProto.SystemEvent_SYSTEM,
		"",
		"",
		map[string]string{"progress_window": "show", "version": pendingVersion.String()},
	)

	updateState := UpdateState{
		PreUpdateVersion: m.currentVersion,
		TargetVersion:    pendingVersion.String(),
	}
	if err := m.stateManager.UpdateState(updateState); err != nil {
		log.Warnf("failed to update state: %v", err)
	} else {
		if err = m.stateManager.PersistState(ctx); err != nil {
			log.Warnf("failed to persist state: %v", err)
		}
	}

	inst := installer.New()
	if err := inst.RunInstallation(ctx, pendingVersion.String()); err != nil {
		log.Errorf("error triggering update: %v", err)
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_ERROR,
			cProto.SystemEvent_SYSTEM,
			"Auto-update failed",
			fmt.Sprintf("Auto-update failed: %v", err),
			nil,
		)
		return err
	}
	return nil
}

// loadAndDeleteUpdateState loads the update state, deletes it from storage, and returns it.
// Returns nil if no state exists.
func (m *Manager) loadAndDeleteUpdateState(ctx context.Context) (*UpdateState, error) {
	stateType := &UpdateState{}

	m.stateManager.RegisterState(stateType)
	if err := m.stateManager.LoadState(stateType); err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	state := m.stateManager.GetState(stateType)
	if state == nil {
		return nil, errNoUpdateState
	}

	updateState, ok := state.(*UpdateState)
	if !ok {
		return nil, fmt.Errorf("failed to cast state to UpdateState")
	}

	if err := m.stateManager.DeleteState(updateState); err != nil {
		return nil, fmt.Errorf("delete state: %w", err)
	}

	if err := m.stateManager.PersistState(ctx); err != nil {
		return nil, fmt.Errorf("persist state: %w", err)
	}

	return updateState, nil
}

func (m *Manager) shouldUpdate(updateVersion *v.Version, forceUpdate bool) bool {
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

	if forceUpdate && time.Since(m.lastTrigger) < 3*time.Minute {
		log.Debugf("skipping auto-update, last update was %s ago", time.Since(m.lastTrigger))
		return false
	}

	return true
}

func (m *Manager) lastResultErrReason() string {
	inst := installer.New()
	result := installer.NewResultHandler(inst.TempDir())
	return result.GetErrorResultReason()
}
