package dns

import (
	"fmt"

	"github.com/miekg/dns"

	nbdns "github.com/netbirdio/netbird/dns"
)

// MockServer is the mock instance of a dns server
type MockServer struct {
	InitializeFunc        func() error
	StopFunc              func()
	UpdateDNSServerFunc   func(serial uint64, update nbdns.Config) error
	RegisterHandlerFunc   func([]string, dns.Handler) error
	UnregisterHandlerFunc func([]string) error
	DeregisterHandlerFunc func([]string) error
}

func (m *MockServer) UnregisterHandler(domains []string) error {
	panic("implement me")
}

func (m *MockServer) RegisterHandler(domains []string, handler dns.Handler) error {
	if m.RegisterHandlerFunc != nil {
		return m.RegisterHandlerFunc(domains, handler)
	}
	return nil
}

func (m *MockServer) DeregisterHandler(domains []string) error {
	if m.DeregisterHandlerFunc != nil {
		return m.DeregisterHandlerFunc(domains)
	}
	return nil
}

// Initialize mock implementation of Initialize from Server interface
func (m *MockServer) Initialize() error {
	if m.InitializeFunc != nil {
		return m.InitializeFunc()
	}
	return nil
}

// Stop mock implementation of Stop from Server interface
func (m *MockServer) Stop() {
	if m.StopFunc != nil {
		m.StopFunc()
	}
}

func (m *MockServer) DnsIP() string {
	return ""
}

func (m *MockServer) OnUpdatedHostDNSServer(strings []string) {
	// TODO implement me
	panic("implement me")
}

// UpdateDNSServer mock implementation of UpdateDNSServer from Server interface
func (m *MockServer) UpdateDNSServer(serial uint64, update nbdns.Config) error {
	if m.UpdateDNSServerFunc != nil {
		return m.UpdateDNSServerFunc(serial, update)
	}
	return fmt.Errorf("method UpdateDNSServer is not implemented")
}

func (m *MockServer) SearchDomains() []string {
	return make([]string, 0)
}

// ProbeAvailability mocks implementation of ProbeAvailability from the Server interface
func (m *MockServer) ProbeAvailability() {
}
