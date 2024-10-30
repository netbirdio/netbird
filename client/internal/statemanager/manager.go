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

	if m.cancel != nil {
		m.cancel()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.done:
			return nil
		}
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
		return fmt.Errorf("state %s not registered", name)
	}

	m.states[name] = state
	m.dirty[name] = struct{}{}

	return nil
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

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	done := make(chan error, 1)

	go func() {
		data, err := json.MarshalIndent(m.states, "", "  ")
		if err != nil {
			done <- fmt.Errorf("marshal states: %w", err)
			return
		}

		// nolint:gosec
		if err := os.WriteFile(m.filePath, data, 0640); err != nil {
			done <- fmt.Errorf("write state file: %w", err)
			return
		}

		done <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
	}

	log.Debugf("persisted shutdown states: %v", maps.Keys(m.dirty))

	clear(m.dirty)

	return nil
}

// loadStateFile reads and unmarshals the state file into a map of raw JSON messages
func (m *Manager) loadStateFile() (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("state file does not exist")
			return nil, nil // nolint:nilnil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var rawStates map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawStates); err != nil {
		log.Warn("State file appears to be corrupted, attempting to delete it")
		if err := os.Remove(m.filePath); err != nil {
			log.Errorf("Failed to delete corrupted state file: %v", err)
		} else {
			log.Info("State file deleted")
		}
		return nil, fmt.Errorf("unmarshal states: %w", err)
	}

	return rawStates, nil
}

// loadSingleRawState unmarshals a raw state into a concrete state object
func (m *Manager) loadSingleRawState(name string, rawState json.RawMessage) (State, error) {
	stateType, ok := m.stateTypes[name]
	if !ok {
		return nil, fmt.Errorf("state %s not registered", name)
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

	rawStates, err := m.loadStateFile()
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

// PerformCleanup retrieves all states from the state file and calls Cleanup on registered states that support it.
// Unregistered states are preserved in their original state.
func (m *Manager) PerformCleanup() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Load raw states from file
	rawStates, err := m.loadStateFile()
	if err != nil {
		log.Warnf("Failed to load state during cleanup: %v", err)
		return err
	}
	if rawStates == nil {
		return nil
	}

	var merr *multierror.Error

	// Process each state in the file
	for name, rawState := range rawStates {
		// For unregistered states, preserve the raw JSON
		if _, registered := m.stateTypes[name]; !registered {
			m.states[name] = &RawState{data: rawState}
			continue
		}

		// Load the registered state
		loadedState, err := m.loadSingleRawState(name, rawState)
		if err != nil {
			merr = multierror.Append(merr, err)
			continue
		}

		if loadedState == nil {
			continue
		}

		// Check if state supports cleanup
		cleanableState, isCleanable := loadedState.(CleanableState)
		if !isCleanable {
			// If it doesn't support cleanup, keep it as-is
			m.states[name] = loadedState
			continue
		}

		// Perform cleanup for cleanable states
		log.Infof("client was not shut down properly, cleaning up %s", name)
		if err := cleanableState.Cleanup(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("cleanup state for %s: %w", name, err))
			// On cleanup error, preserve the state
			m.states[name] = loadedState
		} else {
			// Successfully cleaned up - mark for deletion
			m.states[name] = nil
			m.dirty[name] = struct{}{}
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}
