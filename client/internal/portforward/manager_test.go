//go:build !js

package portforward

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

type mockNAT struct {
	natType          string
	deviceAddr       net.IP
	externalAddr     net.IP
	internalAddr     net.IP
	mappings         map[int]int
	addMappingErr    error
	deleteMappingErr error
}

func newMockNAT() *mockNAT {
	return &mockNAT{
		natType:      "Mock-NAT",
		deviceAddr:   net.ParseIP("192.168.1.1"),
		externalAddr: net.ParseIP("203.0.113.50"),
		internalAddr: net.ParseIP("192.168.1.100"),
		mappings:     make(map[int]int),
	}
}

func (m *mockNAT) Type() string {
	return m.natType
}

func (m *mockNAT) GetDeviceAddress() (net.IP, error) {
	return m.deviceAddr, nil
}

func (m *mockNAT) GetExternalAddress() (net.IP, error) {
	return m.externalAddr, nil
}

func (m *mockNAT) GetInternalAddress() (net.IP, error) {
	return m.internalAddr, nil
}

func (m *mockNAT) AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, timeout time.Duration) (int, error) {
	if m.addMappingErr != nil {
		return 0, m.addMappingErr
	}
	externalPort := internalPort
	m.mappings[internalPort] = externalPort
	return externalPort, nil
}

func (m *mockNAT) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	if m.deleteMappingErr != nil {
		return m.deleteMappingErr
	}
	delete(m.mappings, internalPort)
	return nil
}

func setupTestManager(t *testing.T) (*Manager, context.CancelFunc) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	sm := statemanager.New(statePath)
	sm.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, sm.Stop(ctx))
	})

	m := NewManager(sm)
	m.gateway = newMockNAT()

	ctx, cancel := context.WithCancel(context.Background())
	m.ctx = ctx
	m.cancel = cancel
	m.wgPort = 51820

	sm.RegisterState(&State{})

	return m, cancel
}

func TestManager_CreateMapping(t *testing.T) {
	m, cancel := setupTestManager(t)
	defer cancel()

	err := m.createMapping()
	require.NoError(t, err)

	mapping := m.GetMapping()
	require.NotNil(t, mapping)

	assert.Equal(t, "udp", mapping.Protocol)
	assert.Equal(t, uint16(51820), mapping.InternalPort)
	assert.Equal(t, uint16(51820), mapping.ExternalPort)
	assert.Equal(t, "Mock-NAT", mapping.NATType)
	assert.Equal(t, net.ParseIP("203.0.113.50").To4(), mapping.ExternalIP.To4())
}

func TestManager_GetMapping_ReturnsNilWhenNotReady(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	sm := statemanager.New(statePath)

	m := NewManager(sm)

	assert.Nil(t, m.GetMapping())
}

func TestManager_IsAvailable(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	sm := statemanager.New(statePath)

	m := NewManager(sm)

	// Initially not available (no mapping)
	assert.False(t, m.IsAvailable())

	// Set gateway but no mapping - still not available
	m.gateway = newMockNAT()
	assert.False(t, m.IsAvailable())

	// Add mapping - now available
	m.mapping = &Mapping{InternalPort: 51820}
	assert.True(t, m.IsAvailable())

	// Clear mapping - not available again
	m.mapping = nil
	assert.False(t, m.IsAvailable())
}

func TestState_Cleanup(t *testing.T) {
	state := &State{
		Protocol:     "udp",
		InternalPort: 51820,
	}

	// Cleanup should not error even if NAT discovery fails
	err := state.Cleanup()
	assert.NoError(t, err)
}

func TestState_Name(t *testing.T) {
	state := &State{}
	assert.Equal(t, "port_forward_state", state.Name())
}
