//go:build !js

package portforward

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-nat"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	defaultMappingTTL  = 2 * time.Hour
	renewalInterval    = defaultMappingTTL / 2
	discoveryTimeout   = 10 * time.Second
	mappingDescription = "NetBird"

	envDisableNATMapper = "NB_DISABLE_NAT_MAPPER"
)

type Mapping struct {
	Protocol     string
	InternalPort uint16
	ExternalPort uint16
	ExternalIP   net.IP
	NATType      string
}

type Manager struct {
	ctx          context.Context
	cancel       context.CancelFunc
	stateManager *statemanager.Manager

	mu      sync.RWMutex
	gateway nat.NAT
	mapping *Mapping

	wgPort uint16
	wg     sync.WaitGroup
}

func NewManager(stateManager *statemanager.Manager) *Manager {
	return &Manager{
		stateManager: stateManager,
	}
}

// Start begins async discovery and mapping creation for the given WireGuard port.
// This does not block - use GetMapping() to check if mapping is ready.
func (m *Manager) Start(ctx context.Context, wgPort uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		return
	}

	if isDisabledByEnv() {
		log.Infof("NAT port mapper disabled via %s", envDisableNATMapper)
		return
	}

	if wgPort == 0 {
		log.Warnf("invalid WireGuard port 0; NAT mapping disabled")
		return
	}

	m.ctx, m.cancel = context.WithCancel(ctx)
	m.wgPort = wgPort

	m.stateManager.RegisterState(&State{})

	m.wg.Add(1)
	go m.run()
}

func (m *Manager) run() {
	defer m.wg.Done()

	if err := m.stateManager.LoadState(&State{}); err != nil {
		log.Warnf("failed to load port forward state: %v", err)
	}

	var residualState *State
	if existing := m.stateManager.GetState(&State{}); existing != nil {
		if state, ok := existing.(*State); ok && state.InternalPort != 0 {
			residualState = state
		}
	}

	discoverCtx, discoverCancel := context.WithTimeout(m.ctx, discoveryTimeout)
	defer discoverCancel()

	gateway, err := nat.DiscoverGateway(discoverCtx)
	if err != nil {
		log.Infof("NAT gateway discovery failed: %v (port forwarding disabled)", err)
		return
	}

	m.mu.Lock()
	m.gateway = gateway
	m.mu.Unlock()

	log.Infof("discovered NAT gateway: %s", gateway.Type())

	if residualState != nil {
		if err := m.cleanupResidual(residualState); err != nil {
			log.Warnf("failed to cleanup residual mapping: %v", err)
		}
	}

	if err := m.createMapping(); err != nil {
		log.Warnf("failed to create port mapping: %v", err)
		return
	}

	m.renewLoop()
}

func (m *Manager) cleanupResidual(state *State) error {
	m.mu.RLock()
	gateway := m.gateway
	m.mu.RUnlock()

	if gateway == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	if err := gateway.DeletePortMapping(ctx, state.Protocol, int(state.InternalPort)); err != nil {
		return fmt.Errorf("delete residual mapping: %w", err)
	}

	log.Infof("cleaned up residual port mapping for port %d", state.InternalPort)

	if err := m.stateManager.UpdateState(&State{}); err != nil {
		return fmt.Errorf("clear state after cleanup: %w", err)
	}

	return nil
}

func (m *Manager) createMapping() error {
	m.mu.Lock()
	gateway := m.gateway
	wgPort := m.wgPort
	m.mu.Unlock()

	if gateway == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	externalPort, err := gateway.AddPortMapping(ctx, "udp", int(wgPort), mappingDescription, defaultMappingTTL)
	if err != nil {
		return err
	}

	externalIP, err := gateway.GetExternalAddress()
	if err != nil {
		log.Debugf("failed to get external address: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.gateway != gateway {
		log.Debugf("gateway changed during mapping creation, discarding result")
		return nil
	}

	m.mapping = &Mapping{
		Protocol:     "udp",
		InternalPort: wgPort,
		ExternalPort: uint16(externalPort),
		ExternalIP:   externalIP,
		NATType:      gateway.Type(),
	}

	log.Infof("created port mapping: %d -> %d via %s (external IP: %s)",
		wgPort, externalPort, gateway.Type(), externalIP)

	return m.persistStateLocked()
}

// Stop cancels the manager and attempts to delete the port mapping.
// After Stop returns, the manager cannot be restarted.
func (m *Manager) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	gateway := m.gateway
	mapping := m.mapping
	m.cancel = nil
	m.gateway = nil
	m.mapping = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	m.wg.Wait()

	if gateway == nil || mapping == nil {
		return
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer ctxCancel()

	if err := gateway.DeletePortMapping(ctx, mapping.Protocol, int(mapping.InternalPort)); err != nil {
		log.Debugf("delete port mapping on stop: %v", err)
		return
	}

	log.Infof("deleted port mapping for port %d", mapping.InternalPort)

	if err := m.stateManager.UpdateState(&State{}); err != nil {
		log.Debugf("clear state on stop: %v", err)
	}
}

// GetMapping returns the current mapping if ready, nil otherwise
func (m *Manager) GetMapping() *Mapping {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mapping == nil {
		return nil
	}

	mapping := *m.mapping
	return &mapping
}

// IsAvailable returns true if port forwarding is available and mapping exists
func (m *Manager) IsAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.mapping != nil
}

func (m *Manager) renewLoop() {
	ticker := time.NewTicker(renewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.renewMapping(); err != nil {
				log.Warnf("failed to renew port mapping: %v", err)
			}
		}
	}
}

func (m *Manager) renewMapping() error {
	m.mu.Lock()
	gateway := m.gateway
	mapping := m.mapping
	m.mu.Unlock()

	if mapping == nil || gateway == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	externalPort, err := gateway.AddPortMapping(ctx, mapping.Protocol, int(mapping.InternalPort), mappingDescription, defaultMappingTTL)
	if err != nil {
		return fmt.Errorf("add port mapping: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.gateway != gateway || m.mapping == nil {
		log.Debugf("state changed during mapping renewal, discarding result")
		return nil
	}

	if uint16(externalPort) != m.mapping.ExternalPort {
		log.Warnf("external port changed on renewal: %d -> %d (candidate may be stale)",
			m.mapping.ExternalPort, externalPort)
		m.mapping.ExternalPort = uint16(externalPort)
	}

	log.Debugf("renewed port mapping: %d -> %d", m.mapping.InternalPort, m.mapping.ExternalPort)
	return nil
}

func (m *Manager) persistStateLocked() error {
	var state *State
	if m.mapping != nil {
		state = &State{
			InternalPort: m.mapping.InternalPort,
			Protocol:     m.mapping.Protocol,
		}
	} else {
		state = &State{}
	}

	return m.stateManager.UpdateState(state)
}

func isDisabledByEnv() bool {
	val := os.Getenv(envDisableNATMapper)
	if val == "" {
		return false
	}

	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", envDisableNATMapper, err)
		return false
	}
	return disabled
}
