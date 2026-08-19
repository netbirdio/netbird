//go:build !js

package portforward

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNAT struct {
	natType             string
	deviceAddr          net.IP
	externalAddr        net.IP
	internalAddr        net.IP
	mappings            map[int]int
	addMappingErr       error
	deleteMappingErr    error
	onlyPermanentLeases bool
	lastTimeout         time.Duration
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
	if m.onlyPermanentLeases && timeout != 0 {
		return 0, fmt.Errorf("SOAP fault. Code:  | Explanation:  | Detail: <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError>")
	}
	externalPort := internalPort
	m.mappings[internalPort] = externalPort
	m.lastTimeout = timeout
	return externalPort, nil
}

func (m *mockNAT) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	if m.deleteMappingErr != nil {
		return m.deleteMappingErr
	}
	delete(m.mappings, internalPort)
	return nil
}

func TestManager_CreateMapping(t *testing.T) {
	m := NewManager()
	m.wgPort = 51820

	gateway := newMockNAT()
	mapping, err := m.createMapping(context.Background(), gateway)
	require.NoError(t, err)
	require.NotNil(t, mapping)

	assert.Equal(t, "udp", mapping.Protocol)
	assert.Equal(t, uint16(51820), mapping.InternalPort)
	assert.Equal(t, uint16(51820), mapping.ExternalPort)
	assert.Equal(t, "Mock-NAT", mapping.NATType)
	assert.Equal(t, net.ParseIP("203.0.113.50").To4(), mapping.ExternalIP.To4())
	assert.Equal(t, defaultMappingTTL, mapping.TTL)
}

func TestManager_GetMapping_ReturnsNilWhenNotReady(t *testing.T) {
	m := NewManager()
	assert.Nil(t, m.GetMapping())
}

func TestManager_GetMapping_ReturnsCopy(t *testing.T) {
	m := NewManager()
	m.mapping = &Mapping{
		Protocol:     "udp",
		InternalPort: 51820,
		ExternalPort: 51820,
	}

	mapping := m.GetMapping()
	require.NotNil(t, mapping)
	assert.Equal(t, uint16(51820), mapping.InternalPort)

	// Mutating the returned copy should not affect the manager's mapping.
	mapping.ExternalPort = 9999
	assert.Equal(t, uint16(51820), m.GetMapping().ExternalPort)
}

func TestManager_Cleanup_DeletesMapping(t *testing.T) {
	m := NewManager()
	m.mapping = &Mapping{
		Protocol:     "udp",
		InternalPort: 51820,
		ExternalPort: 51820,
	}

	gateway := newMockNAT()
	// Seed the mock so we can verify deletion.
	gateway.mappings[51820] = 51820

	m.cleanup(context.Background(), gateway)

	_, exists := gateway.mappings[51820]
	assert.False(t, exists, "mapping should be deleted from gateway")
	assert.Nil(t, m.GetMapping(), "in-memory mapping should be cleared")
}

func TestManager_Cleanup_NilMapping(t *testing.T) {
	m := NewManager()
	gateway := newMockNAT()

	// Should not panic or call gateway.
	m.cleanup(context.Background(), gateway)
}


func TestManager_CreateMapping_PermanentLeaseFallback(t *testing.T) {
	m := NewManager()
	m.wgPort = 51820

	gateway := newMockNAT()
	gateway.onlyPermanentLeases = true

	mapping, err := m.createMapping(context.Background(), gateway)
	require.NoError(t, err)
	require.NotNil(t, mapping)

	assert.Equal(t, uint16(51820), mapping.InternalPort)
	assert.Equal(t, time.Duration(0), mapping.TTL, "should return zero TTL for permanent lease")
	assert.Equal(t, time.Duration(0), gateway.lastTimeout, "should have retried with zero duration")
}

func TestIsPermanentLeaseRequired(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "UPnP error 725",
			err:      fmt.Errorf("SOAP fault. Code:  | Detail: <UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError>"),
			expected: true,
		},
		{
			name:     "wrapped error with 725",
			err:      fmt.Errorf("add port mapping: %w", fmt.Errorf("Detail: <errorCode>725</errorCode>")),
			expected: true,
		},
		{
			name:     "error 725 with newlines in XML",
			err:      fmt.Errorf("<errorCode>\n  725\n</errorCode>"),
			expected: true,
		},
		{
			name:     "bare 725 without XML tag",
			err:      fmt.Errorf("error code 725"),
			expected: false,
		},
		{
			name:     "unrelated error",
			err:      fmt.Errorf("connection refused"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isPermanentLeaseRequired(tt.err))
		})
	}
}
