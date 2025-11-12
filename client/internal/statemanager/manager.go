package statemanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/util"
)

const (
	errStateNotRegistered = "state %s not registered"
	errLoadStateFile      = "load state file: %w"
)

// State interface defines the methods that all state types must implement
type State interface {
	Name() string
}

// CleanableState interface extends State with cleanup capability
type CleanableState interface {
	State
	Cleanup() error
}

// RawState wraps raw JSON data for unregistered states
type RawState struct {
	data json.RawMessage
}

func (r *RawState) Name() string {
	return "" // This is a placeholder implementation
}

// MarshalJSON implements json.Marshaler to preserve the original JSON
func (r *RawState) MarshalJSON() ([]byte, error) {
	return r.data, nil
}

// Manager handles the persistence and management of various states
type Manager struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	filePath string
	// holds the states that are registered with the manager and that are to be persisted
	states map[string]State
	// holds the state names that have been updated and need to be persisted with the next save
	dirty map[string]struct{}
	// holds the type information for each registered state
	stateTypes map[string]reflect.Type
}

// New creates a new Manager instance
func New(filePath string) *Manager {
	return &Manager{
		filePath:   filePath,
		states:     make(map[string]State),
		dirty:      make(map[string]struct{}),
		stateTypes: make(map[string]reflect.Type),
	}
}

// Start starts the state manager periodic save routine
func (m *Manager) Start() {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var ctx context.Context
	ctx, m.cancel = context.WithCancel(context.Background())
	m.done = make(chan struct{})

	go m.periodicStateSave(ctx)
}

func (m *Manager) Stop(ctx context.Context) error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel == nil {
		return nil
	}
	m.cancel()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
	}

	return nil
}

// RegisterState registers a state with the manager but doesn't attempt to persist it.
// Pass an uninitialized state to register it.
func (m *Manager) RegisterState(state State) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	name := state.Name()
	m.states[name] = nil
	m.stateTypes[name] = reflect.TypeOf(state).Elem()
}

// GetState returns the state for the given type
func (m *Manager) GetState(state State) State {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.states[state.Name()]
}

// UpdateState updates the state in the manager and marks it as dirty for the next save.
// The state will be replaced with the new one.
func (m *Manager) UpdateState(state State) error {
	if m == nil {
		return nil
	}

	return m.setState(state.Name(), state)
}

// DeleteState removes the state from the manager and marks it as dirty for the next save.
// Pass an uninitialized state to delete it.
func (m *Manager) DeleteState(state State) error {
	if m == nil {
		return nil
	}

	return m.setState(state.Name(), nil)
}

func (m *Manager) setState(name string, state State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.states[name]; !exists {
		return fmt.Errorf(errStateNotRegistered, name)
	}

	m.states[name] = state
	m.dirty[name] = struct{}{}

	return nil
}

// DeleteStateByName handles deletion of states without cleanup.
// It doesn't require the state to be registered.
func (m *Manager) DeleteStateByName(stateName string) error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rawStates, err := m.loadStateFile(false)
	if err != nil {
		return fmt.Errorf(errLoadStateFile, err)
	}
	if rawStates == nil {
		return nil
	}

	if _, exists := rawStates[stateName]; !exists {
		return fmt.Errorf("state %s not found", stateName)
	}

	// Mark state as deleted by setting it to nil and marking it dirty
	m.states[stateName] = nil
	m.dirty[stateName] = struct{}{}

	return nil
}

// DeleteAllStates removes all states.
func (m *Manager) DeleteAllStates() (int, error) {
	if m == nil {
		return 0, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rawStates, err := m.loadStateFile(false)
	if err != nil {
		return 0, fmt.Errorf(errLoadStateFile, err)
	}
	if rawStates == nil {
		return 0, nil
	}

	count := len(rawStates)

	// Mark all states as deleted and dirty
	for name := range rawStates {
		m.states[name] = nil
		m.dirty[name] = struct{}{}
	}

	return count, nil
}

func (m *Manager) periodicStateSave(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer close(m.done)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.PersistState(ctx); err != nil {
				log.Errorf("failed to persist state: %v", err)
			}
		}
	}
}

// PersistState persists the states that have been updated since the last save.
func (m *Manager) PersistState(ctx context.Context) error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.dirty) == 0 {
		return nil
	}

	bs, err := marshalWithPanicRecovery(m.states)
	if err != nil {
		return fmt.Errorf("marshal states: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- util.WriteBytesWithRestrictedPermission(ctx, m.filePath, bs)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
	}

	log.Debugf("persisted states: %v, took %v", maps.Keys(m.dirty), time.Since(start))

	clear(m.dirty)

	return nil
}

// loadStateFile reads and unmarshals the state file into a map of raw JSON messages
func (m *Manager) loadStateFile(deleteCorrupt bool) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debugf("state file %s does not exist", m.filePath)
			return nil, nil // nolint:nilnil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var rawStates map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawStates); err != nil {
		m.handleCorruptedState(deleteCorrupt)
		return nil, fmt.Errorf("unmarshal states: %w", err)
	}

	return rawStates, nil
}

// handleCorruptedState creates a backup of a corrupted state file by moving it
func (m *Manager) handleCorruptedState(deleteCorrupt bool) {
	if !deleteCorrupt {
		return
	}
	log.Warn("State file appears to be corrupted, attempting to back it up")

	backupPath := fmt.Sprintf("%s.corrupted.%d", m.filePath, time.Now().UnixNano())
	if err := os.Rename(m.filePath, backupPath); err != nil {
		log.Errorf("Failed to backup corrupted state file: %v", err)
		return
	}

	log.Infof("Created backup of corrupted state file at: %s", backupPath)
}

// loadSingleRawState unmarshals a raw state into a concrete state object
func (m *Manager) loadSingleRawState(name string, rawState json.RawMessage) (State, error) {
	stateType, ok := m.stateTypes[name]
	if !ok {
		return nil, fmt.Errorf(errStateNotRegistered, name)
	}

	if string(rawState) == "null" {
		return nil, nil //nolint:nilnil
	}

	statePtr := reflect.New(stateType).Interface().(State)
	if err := json.Unmarshal(rawState, statePtr); err != nil {
		return nil, fmt.Errorf("unmarshal state %s: %w", name, err)
	}

	return statePtr, nil
}

// LoadState loads a specific state from the state file
func (m *Manager) LoadState(state State) error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rawStates, err := m.loadStateFile(false)
	if err != nil {
		return err
	}
	if rawStates == nil {
		return nil
	}

	name := state.Name()
	rawState, exists := rawStates[name]
	if !exists {
		return nil
	}

	loadedState, err := m.loadSingleRawState(name, rawState)
	if err != nil {
		return err
	}

	m.states[name] = loadedState
	if loadedState != nil {
		log.Debugf("loaded state: %s", name)
	}

	return nil
}

// cleanupSingleState handles the cleanup of a specific state and returns any error.
// The caller must hold the mutex.
func (m *Manager) cleanupSingleState(name string, rawState json.RawMessage) error {
	// For unregistered states, preserve the raw JSON
	if _, registered := m.stateTypes[name]; !registered {
		m.states[name] = &RawState{data: rawState}
		return nil
	}

	// Load the state
	loadedState, err := m.loadSingleRawState(name, rawState)
	if err != nil {
		return err
	}

	if loadedState == nil {
		return nil
	}

	// Check if state supports cleanup
	cleanableState, isCleanable := loadedState.(CleanableState)
	if !isCleanable {
		// If it doesn't support cleanup, keep it as-is
		m.states[name] = loadedState
		return nil
	}

	// Perform cleanup
	log.Infof("cleaning up state %s", name)
	if err := cleanableState.Cleanup(); err != nil {
		// On cleanup error, preserve the state
		m.states[name] = loadedState
		return fmt.Errorf("cleanup state: %w", err)
	}

	// Successfully cleaned up - mark for deletion
	m.states[name] = nil
	m.dirty[name] = struct{}{}
	return nil
}

// CleanupStateByName loads and cleans up a specific state by name if it implements CleanableState.
// Returns an error if the state doesn't exist, isn't registered, or cleanup fails.
func (m *Manager) CleanupStateByName(name string) error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if state is registered
	if _, registered := m.stateTypes[name]; !registered {
		return fmt.Errorf(errStateNotRegistered, name)
	}

	// Load raw states from file
	rawStates, err := m.loadStateFile(false)
	if err != nil {
		return err
	}
	if rawStates == nil {
		return nil
	}

	// Check if state exists in file
	rawState, exists := rawStates[name]
	if !exists {
		return nil
	}

	if err := m.cleanupSingleState(name, rawState); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	return nil
}

// PerformCleanup retrieves all states from the state file and calls Cleanup on registered states that support it.
// Unregistered states are preserved in their original state.
func (m *Manager) PerformCleanup() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Load raw states from file
	rawStates, err := m.loadStateFile(true)
	if err != nil {
		return fmt.Errorf(errLoadStateFile, err)
	}
	if rawStates == nil {
		return nil
	}

	var merr *multierror.Error

	// Process each state in the file
	for name, rawState := range rawStates {
		if err := m.cleanupSingleState(name, rawState); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", name, err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// GetSavedStateNames returns all state names that are currently saved in the state file.
func (m *Manager) GetSavedStateNames() ([]string, error) {
	if m == nil {
		return nil, nil
	}

	rawStates, err := m.loadStateFile(false)
	if err != nil {
		return nil, fmt.Errorf(errLoadStateFile, err)
	}
	if rawStates == nil {
		return nil, nil
	}

	var states []string
	for name, state := range rawStates {
		if len(state) != 0 && string(state) != "null" {
			states = append(states, name)
		}
	}

	return states, nil
}

func marshalWithPanicRecovery(v any) ([]byte, error) {
	var bs []byte
	var err error

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic during marshal: %v", r)
			}
		}()
		bs, err = json.Marshal(v)
	}()

	return bs, err
}
