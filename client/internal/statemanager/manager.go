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

// State interface defines the methods that all state types must implement
type State interface {
	Name() string
	Cleanup() error
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

	bs, err := json.MarshalIndent(m.states, "", "    ")
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

	log.Debugf("persisted shutdown states: %v, took %v", maps.Keys(m.dirty), time.Since(start))

	clear(m.dirty)

	return nil
}

// loadState loads the existing state from the state file
func (m *Manager) loadState() error {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("state file does not exist")
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}

	var rawStates map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawStates); err != nil {
		log.Warn("State file appears to be corrupted, attempting to delete it")
		if err := os.Remove(m.filePath); err != nil {
			log.Errorf("Failed to delete corrupted state file: %v", err)
		} else {
			log.Info("State file deleted")
		}
		return fmt.Errorf("unmarshal states: %w", err)
	}

	var merr *multierror.Error

	for name, rawState := range rawStates {
		stateType, ok := m.stateTypes[name]
		if !ok {
			merr = multierror.Append(merr, fmt.Errorf("unknown state type: %s", name))
			continue
		}

		if string(rawState) == "null" {
			continue
		}

		statePtr := reflect.New(stateType).Interface().(State)
		if err := json.Unmarshal(rawState, statePtr); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("unmarshal state %s: %w", name, err))
			continue
		}

		m.states[name] = statePtr
		log.Debugf("loaded state: %s", name)
	}

	return nberrors.FormatErrorOrNil(merr)
}

// PerformCleanup retrieves all states from the state file for the registered states and calls Cleanup on them.
// If the cleanup is successful, the state is marked for deletion.
func (m *Manager) PerformCleanup() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.loadState(); err != nil {
		log.Warnf("Failed to load state during cleanup: %v", err)
	}

	var merr *multierror.Error
	for name, state := range m.states {
		if state == nil {
			// If no state was found in the state file, we don't mark the state dirty nor return an error
			continue
		}

		log.Infof("client was not shut down properly, cleaning up %s", name)
		if err := state.Cleanup(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("cleanup state for %s: %w", name, err))
		} else {
			// mark for deletion on cleanup success
			m.states[name] = nil
			m.dirty[name] = struct{}{}
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}
