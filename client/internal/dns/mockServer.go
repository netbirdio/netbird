package dns

import (
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
)

// MockServer is the mock instance of a dns server
type MockServer struct {
	StartFunc           func()
	StopFunc            func()
	UpdateDNSServerFunc func(serial uint64, update nbdns.Config) error
}

// Start mock implementation of Start from Server interface
func (m *MockServer) Start() {
	if m.StartFunc != nil {
		m.StartFunc()
	}
}

// Stop mock implementation of Stop from Server interface
func (m *MockServer) Stop() {
	if m.StopFunc != nil {
		m.StopFunc()
	}
}

// UpdateDNSServer mock implementation of UpdateDNSServer from Server interface
func (m *MockServer) UpdateDNSServer(serial uint64, update nbdns.Config) error {
	if m.UpdateDNSServerFunc != nil {
		return m.UpdateDNSServerFunc(serial, update)
	}
	return fmt.Errorf("method UpdateDNSServer is not implemented")
}
