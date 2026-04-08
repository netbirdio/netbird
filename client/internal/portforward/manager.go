//go:build !js

package portforward

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-nat"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/portforward/pcp"
)

const (
	defaultMappingTTL   = 2 * time.Hour
	renewalInterval     = defaultMappingTTL / 2
	healthCheckInterval = 1 * time.Minute
	discoveryTimeout    = 10 * time.Second
	mappingDescription  = "NetBird"
)

type Mapping struct {
	Protocol     string
	InternalPort uint16
	ExternalPort uint16
	ExternalIP   net.IP
	NATType      string
}

type Manager struct {
	cancel context.CancelFunc

	mapping     *Mapping
	mappingLock sync.Mutex

	wgPort uint16

	done    chan struct{}
	stopCtx chan context.Context

	// protect exported functions
	mu sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		stopCtx: make(chan context.Context, 1),
	}
}

func (m *Manager) Start(ctx context.Context, wgPort uint16) {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}

	if isDisabledByEnv() {
		log.Infof("NAT port mapper disabled via %s", envDisableNATMapper)
		m.mu.Unlock()
		return
	}

	if wgPort == 0 {
		log.Warnf("invalid WireGuard port 0; NAT mapping disabled")
		m.mu.Unlock()
		return
	}
	m.wgPort = wgPort

	m.done = make(chan struct{})
	defer close(m.done)

	ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()

	gateway, mapping, err := m.setup(ctx)
	if err != nil {
		log.Errorf("failed to setup NAT port mapping: %v", err)

		return
	}

	m.mappingLock.Lock()
	m.mapping = mapping
	m.mappingLock.Unlock()

	m.renewLoop(ctx, gateway)

	select {
	case cleanupCtx := <-m.stopCtx:
		// block the Start while cleaned up gracefully
		m.cleanup(cleanupCtx, gateway)
	default:
		// return Start immediately and cleanup in background
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		go func() {
			defer cleanupCancel()
			m.cleanup(cleanupCtx, gateway)
		}()
	}
}

// GetMapping returns the current mapping if ready, nil otherwise
func (m *Manager) GetMapping() *Mapping {
	m.mappingLock.Lock()
	defer m.mappingLock.Unlock()

	if m.mapping == nil {
		return nil
	}

	mapping := *m.mapping
	return &mapping
}

// GracefullyStop cancels the manager and attempts to delete the port mapping.
// After GracefullyStop returns, the manager cannot be restarted.
func (m *Manager) GracefullyStop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel == nil {
		return nil
	}

	// Send cleanup context before cancelling, so Start picks it up after renewLoop exits.
	m.startTearDown(ctx)

	m.cancel()
	m.cancel = nil

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return nil
	}
}

func (m *Manager) setup(ctx context.Context) (nat.NAT, *Mapping, error) {
	discoverCtx, discoverCancel := context.WithTimeout(ctx, discoveryTimeout)
	defer discoverCancel()

	gateway, err := discoverGateway(discoverCtx)
	if err != nil {
		log.Infof("NAT gateway discovery failed: %v (port forwarding disabled)", err)
		return nil, nil, err
	}

	log.Infof("discovered NAT gateway: %s", gateway.Type())

	mapping, err := m.createMapping(ctx, gateway)
	if err != nil {
		log.Warnf("failed to create port mapping: %v", err)
		return nil, nil, err
	}
	return gateway, mapping, nil
}

func (m *Manager) createMapping(ctx context.Context, gateway nat.NAT) (*Mapping, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	externalPort, err := gateway.AddPortMapping(ctx, "udp", int(m.wgPort), mappingDescription, defaultMappingTTL)
	if err != nil {
		return nil, err
	}

	externalIP, err := gateway.GetExternalAddress()
	if err != nil {
		log.Debugf("failed to get external address: %v", err)
	}

	mapping := &Mapping{
		Protocol:     "udp",
		InternalPort: m.wgPort,
		ExternalPort: uint16(externalPort),
		ExternalIP:   externalIP,
		NATType:      gateway.Type(),
	}

	log.Infof("created port mapping: %d -> %d via %s (external IP: %s)",
		m.wgPort, externalPort, gateway.Type(), externalIP)
	return mapping, nil
}

func (m *Manager) renewLoop(ctx context.Context, gateway nat.NAT) {
	renewTicker := time.NewTicker(renewalInterval)
	healthTicker := time.NewTicker(healthCheckInterval)
	defer renewTicker.Stop()
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-renewTicker.C:
			if err := m.renewMapping(ctx, gateway); err != nil {
				log.Warnf("failed to renew port mapping: %v", err)
				continue
			}
		case <-healthTicker.C:
			if m.checkHealthAndRecreate(ctx, gateway) {
				renewTicker.Reset(renewalInterval)
			}
		}
	}
}

func (m *Manager) checkHealthAndRecreate(ctx context.Context, gateway nat.NAT) bool {
	if isHealthCheckDisabled() {
		return false
	}

	m.mappingLock.Lock()
	hasMapping := m.mapping != nil
	m.mappingLock.Unlock()

	if !hasMapping {
		return false
	}

	pcpNAT, ok := gateway.(*pcp.NAT)
	if !ok {
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	epoch, serverRestarted, err := pcpNAT.CheckServerHealth(ctx)
	if err != nil {
		log.Debugf("PCP health check failed: %v", err)
		return false
	}

	if serverRestarted {
		log.Warnf("PCP server restart detected (epoch=%d), recreating port mapping", epoch)
		if err := m.renewMapping(ctx, gateway); err != nil {
			log.Errorf("failed to recreate port mapping after server restart: %v", err)
			return false
		}
		return true
	}

	return false
}

func (m *Manager) renewMapping(ctx context.Context, gateway nat.NAT) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	externalPort, err := gateway.AddPortMapping(ctx, m.mapping.Protocol, int(m.mapping.InternalPort), mappingDescription, defaultMappingTTL)
	if err != nil {
		return fmt.Errorf("add port mapping: %w", err)
	}

	if uint16(externalPort) != m.mapping.ExternalPort {
		log.Warnf("external port changed on renewal: %d -> %d (candidate may be stale)", m.mapping.ExternalPort, externalPort)
		m.mappingLock.Lock()
		m.mapping.ExternalPort = uint16(externalPort)
		m.mappingLock.Unlock()
	}

	log.Debugf("renewed port mapping: %d -> %d", m.mapping.InternalPort, m.mapping.ExternalPort)
	return nil
}

func (m *Manager) cleanup(ctx context.Context, gateway nat.NAT) {
	m.mappingLock.Lock()
	mapping := m.mapping
	m.mapping = nil
	m.mappingLock.Unlock()

	if mapping == nil {
		return
	}

	if err := gateway.DeletePortMapping(ctx, mapping.Protocol, int(mapping.InternalPort)); err != nil {
		log.Warnf("delete port mapping on stop: %v", err)
		return
	}

	log.Infof("deleted port mapping for port %d", mapping.InternalPort)
}

func (m *Manager) startTearDown(ctx context.Context) {
	select {
	case m.stopCtx <- ctx:
	default:
	}
}

