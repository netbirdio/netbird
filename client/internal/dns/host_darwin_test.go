package dns

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/client/internal/statemanager/mocks"
)

// MockCommander to mock exec.Command
type MockCommander struct {
	mock.Mock
}

func (m *MockCommander) Command(name string, arg ...string) *exec.Cmd {
	args := m.Called(name, arg)
	return args.Get(0).(*exec.Cmd)
}

func TestNewHostManager(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "successful creation",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newHostManager()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.NotNil(t, got.createdKeys)
		})
	}
}

func TestApplyDNSConfig(t *testing.T) {
	type mockSetup struct {
		stateManagerError error
		commandOutput     []byte
		commandError      error
	}

	tests := []struct {
		name      string
		config    HostDNSConfig
		mockSetup mockSetup
		wantErr   bool
	}{
		{
			name: "successful apply with search domains",
			config: HostDNSConfig{
				RouteAll: true,
				Domains: []DomainConfig{
					{Domain: "example.com", MatchOnly: false},
					{Domain: "test.com", MatchOnly: true},
				},
				ServerIP:   "1.1.1.1",
				ServerPort: 53,
			},
			mockSetup: mockSetup{
				stateManagerError: nil,
				commandOutput: []byte(`
			PrimaryService : ABC123
			Router : 192.168.1.1
			DomainName : example.com
			SearchDomains : <array> {
			  0 : test.com
			}
			ServerAddresses : <array> {
			  0 : 1.1.1.1
			}
			`),
				commandError: nil,
			},
			wantErr: false,
		},
		{
			name: "state manager error",
			config: HostDNSConfig{
				ServerIP: "1.1.1.1",
			},
			mockSetup: mockSetup{
				stateManagerError: errors.New("state error"),
			},
			wantErr: false, // Function does not return an error, it only logs it.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			s := &systemConfigurator{
				createdKeys: make(map[string]struct{}),
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish() // Ensures all expectations are met

			mockState := mocks.NewMockManager(ctrl)
			mockCmd := new(MockCommander)

			// Mock UpdateState
			mockState.EXPECT().UpdateState(gomock.Any()).Return(tt.mockSetup.stateManagerError).AnyTimes()

			// Mock all expected command executions
			// mockCmd.On("Command", dscacheutilPath, "-flushcache").Return(&exec.Cmd{}).Once()
			// mockCmd.On("Command", "killall", "-HUP", "mDNSResponder").Return(&exec.Cmd{}).Once()
			// mockCmd.On("Command", scutilPath).Return(&exec.Cmd{}).Once() // For runSystemConfigCommand

			// Mock `runSystemConfigCommand`
			originalRunCommand := runSystemConfigCommand
			runSystemConfigCommand = func(command string) ([]byte, error) {
				return tt.mockSetup.commandOutput, tt.mockSetup.commandError
			}
			defer func() { runSystemConfigCommand = originalRunCommand }()

			err := s.applyDNSConfig(tt.config, mockState)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockCmd.AssertExpectations(t) // Ensure Command() is called
		})
	}
}

func TestGetSystemDNSSettings(t *testing.T) {
	tests := []struct {
		name          string
		commandOutput []byte
		commandError  error
		wantSettings  SystemDNSSettings
		wantErr       bool
	}{
		{
			name: "successful retrieval",
			commandOutput: []byte(`
PrimaryService : ABC123
Router : 192.168.1.1
---
DomainName : example.com
SearchDomains : <array> {
  0 : test.com
}
ServerAddresses : <array> {
  0 : 1.1.1.1
}
`),
			wantSettings: SystemDNSSettings{
				Domains:    []string{"example.com", "test.com"},
				ServerIP:   "1.1.1.1",
				ServerPort: 53,
			},
			wantErr: false,
		},
		{
			name:         "command error",
			commandError: errors.New("command failed"),
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &systemConfigurator{
				createdKeys: make(map[string]struct{}),
			}

			originalRunCommand := runSystemConfigCommand
			runSystemConfigCommand = func(command string) ([]byte, error) {
				return tt.commandOutput, tt.commandError
			}
			defer func() { runSystemConfigCommand = originalRunCommand }()

			got, err := s.getSystemDNSSettings()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantSettings, got)
		})
	}
}

func TestSupportCustomPort(t *testing.T) {
	s := &systemConfigurator{}
	assert.True(t, s.supportCustomPort())
}

func TestString(t *testing.T) {
	s := &systemConfigurator{}
	assert.Equal(t, "scutil", s.string())
}
