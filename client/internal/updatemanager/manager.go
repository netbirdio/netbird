//go:build windows || darwin

package updatemanager

import (
	"context"
	"errors"
	"fmt"
	"runtime"
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

	triggerUpdateFn func(context.Context, string) error
}

func NewManager(statusRecorder *peer.Status, stateManager *statemanager.Manager) (*Manager, error) {
	if runtime.GOOS == "darwin" {
		isBrew := !installer.TypeOfInstaller(context.Background()).Downloadable()
		if isBrew {
			log.Warnf("auto-update disabled on Home Brew installation")
			return nil, fmt.Errorf("auto-update not supported on Home Brew installation yet")
		}
	}
	return newManager(statusRecorder, stateManager)
}

func newManager(statusRecorder *peer.Status, stateManager *statemanager.Manager) (*Manager, error) {
	manager := &Manager{
		statusRecorder: statusRecorder,
		stateManager:   stateManager,
		mgmUpdateChan:  make(chan struct{}, 1),
		updateChannel:  make(chan struct{}, 1),
		currentVersion: version.NetbirdVersion(),
		update:         version.NewUpdate("nb/client"),
	}
	manager.triggerUpdateFn = manager.triggerUpdate

	stateManager.RegisterState(&UpdateState{})

	return manager, nil
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
		log.Errorf("manager not started")
		return
	}

	m.updateMutex.Lock()
	defer m.updateMutex.Unlock()

	if expectedVersion == "" {
		log.Errorf("empty expected version provided")
		m.expectedVersion = nil
		m.updateToLatestVersion = false
		return
	}

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

	m.lastTrigger = time.Now()
	log.Infof("Auto-update triggered, current version: %s, target version: %s", m.currentVersion, updateVersion)
	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_CRITICAL,
		cProto.SystemEvent_SYSTEM,
		"Automatically updating client",
		"Your client version is older than auto-update version set in Management, updating client now.",
		nil,
	)

	m.statusRecorder.PublishEvent(
		cProto.SystemEvent_CRITICAL,
		cProto.SystemEvent_SYSTEM,
		"",
		"",
		map[string]string{"progress_window": "show", "version": updateVersion.String()},
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

	if err := m.triggerUpdateFn(ctx, updateVersion.String()); err != nil {
		log.Errorf("Error triggering auto-update: %v", err)
		m.statusRecorder.PublishEvent(
			cProto.SystemEvent_ERROR,
			cProto.SystemEvent_SYSTEM,
			"Auto-update failed",
			fmt.Sprintf("Auto-update failed: %v", err),
			nil,
		)
	}
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

func (m *Manager) lastResultErrReason() string {
	inst := installer.New()
	result := installer.NewResultHandler(inst.TempDir())
	return result.GetErrorResultReason()
}

func (m *Manager) triggerUpdate(ctx context.Context, targetVersion string) error {
	inst := installer.New()
	return inst.RunInstallation(ctx, targetVersion)
}
