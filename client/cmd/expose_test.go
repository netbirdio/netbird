package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

func TestExposeCmdHasTargetHostFlag(t *testing.T) {
	flag := exposeCmd.Flags().Lookup("with-target-host")
	require.NotNil(t, flag, "--with-target-host must be registered")
	assert.Contains(t, flag.Usage, "other-service", "help text should include an example host")
	assert.Contains(t, exposeCmd.Example, "--with-target-host other-service")
}

func TestValidateExposeFlags(t *testing.T) {
	tests := []struct {
		name       string
		port       string
		protocol   string
		targetHost string
		setHost    bool
		wantErr    string
		wantHost   string
		wantPort   uint64
	}{
		{
			name:     "local port without target host",
			port:     "8080",
			protocol: "http",
			wantPort: 8080,
		},
		{
			name:       "hostname",
			port:       "8080",
			protocol:   "http",
			targetHost: "other-service",
			setHost:    true,
			wantHost:   "other-service",
			wantPort:   8080,
		},
		{
			name:       "ipv4",
			port:       "8080",
			protocol:   "tcp",
			targetHost: "10.0.0.29",
			setHost:    true,
			wantHost:   "10.0.0.29",
			wantPort:   8080,
		},
		{
			name:       "overlay peer ip",
			port:       "9000",
			protocol:   "http",
			targetHost: "100.64.0.5",
			setHost:    true,
			wantHost:   "100.64.0.5",
			wantPort:   9000,
		},
		{
			name:       "ipv6 without brackets",
			port:       "8080",
			protocol:   "http",
			targetHost: "2001:db8::1",
			setHost:    true,
			wantHost:   "2001:db8::1",
			wantPort:   8080,
		},
		{
			name:       "ipv6 with brackets",
			port:       "8080",
			protocol:   "http",
			targetHost: "[2001:db8::1]",
			setHost:    true,
			wantHost:   "2001:db8::1",
			wantPort:   8080,
		},
		{
			name:       "hostname with surrounding space",
			port:       "8080",
			protocol:   "http",
			targetHost: "  other-service  ",
			setHost:    true,
			wantHost:   "other-service",
			wantPort:   8080,
		},
		{
			name:       "empty host flag",
			port:       "8080",
			protocol:   "http",
			targetHost: "",
			setHost:    true,
			wantErr:    "target host cannot be empty",
		},
		{
			name:       "whitespace host flag",
			port:       "8080",
			protocol:   "http",
			targetHost: "   ",
			setHost:    true,
			wantErr:    "target host cannot be empty",
		},
		{
			name:       "scheme rejected",
			port:       "8080",
			protocol:   "http",
			targetHost: "http://other-service",
			setHost:    true,
			wantErr:    "scheme",
		},
		{
			name:       "https scheme rejected",
			port:       "8080",
			protocol:   "http",
			targetHost: "https://other-service",
			setHost:    true,
			wantErr:    "scheme",
		},
		{
			name:       "port rejected",
			port:       "8080",
			protocol:   "http",
			targetHost: "other-service:8080",
			setHost:    true,
			wantErr:    "port",
		},
		{
			name:       "ipv4 with port rejected",
			port:       "8080",
			protocol:   "http",
			targetHost: "10.0.0.29:8080",
			setHost:    true,
			wantErr:    "port",
		},
		{
			name:       "ipv6 with port rejected",
			port:       "8080",
			protocol:   "http",
			targetHost: "[2001:db8::1]:8080",
			setHost:    true,
			wantErr:    "port",
		},
		{
			name:       "path rejected",
			port:       "8080",
			protocol:   "http",
			targetHost: "other-service/app",
			setHost:    true,
			wantErr:    "path",
		},
		{
			name:       "loopback ipv4",
			port:       "8080",
			protocol:   "http",
			targetHost: "127.0.0.1",
			setHost:    true,
			wantErr:    "loopback",
		},
		{
			name:       "loopback ipv6",
			port:       "8080",
			protocol:   "http",
			targetHost: "::1",
			setHost:    true,
			wantErr:    "loopback",
		},
		{
			name:       "loopback ipv6 brackets",
			port:       "8080",
			protocol:   "http",
			targetHost: "[::1]",
			setHost:    true,
			wantErr:    "loopback",
		},
		{
			name:       "localhost",
			port:       "8080",
			protocol:   "http",
			targetHost: "localhost",
			setHost:    true,
			wantErr:    "loopback",
		},
		{
			name:       "mapped loopback",
			port:       "8080",
			protocol:   "http",
			targetHost: "::ffff:127.0.0.1",
			setHost:    true,
			wantErr:    "loopback",
		},
		{
			name:     "invalid port",
			port:     "not-a-port",
			protocol: "http",
			wantErr:  "invalid port number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newExposeFlagCmd(t)
			if tt.setHost {
				require.NoError(t, cmd.Flags().Set("with-target-host", tt.targetHost))
			}
			exposeProtocol = tt.protocol

			port, err := validateExposeFlags(cmd, tt.port)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPort, port, "parsed port")
			assert.Equal(t, tt.wantHost, exposeTargetHost, "normalized target host")
		})
	}
}

func TestPrintExposeReadyTargetHost(t *testing.T) {
	t.Cleanup(resetExposeFlagVars)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	exposeProtocol = "http"
	exposeTargetHost = "other-service"
	exposeExternalPort = 0

	printExposeReady(cmd, &proto.ExposeServiceReady{
		ServiceName: "svc",
		ServiceUrl:  "https://svc.example.com",
		Domain:      "svc.example.com",
	}, 8080)

	out := buf.String()
	assert.Contains(t, out, "-> other-service:8080", "ready output should mention the remote target")
	assert.Contains(t, out, "Internal: 8080", "local port line should remain")
}

func TestPrintExposeReadyWithoutTargetHost(t *testing.T) {
	t.Cleanup(resetExposeFlagVars)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	exposeProtocol = "http"
	exposeTargetHost = ""
	exposeExternalPort = 0

	printExposeReady(cmd, &proto.ExposeServiceReady{
		ServiceName: "svc",
		ServiceUrl:  "https://svc.example.com",
		Domain:      "svc.example.com",
	}, 8080)

	assert.NotContains(t, buf.String(), "Target:", "default ready output must not mention a remote target")
}

func newExposeFlagCmd(t *testing.T) *cobra.Command {
	t.Helper()
	resetExposeFlagVars()
	t.Cleanup(resetExposeFlagVars)

	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&exposePin, "with-pin", "", "")
	cmd.Flags().StringVar(&exposePassword, "with-password", "", "")
	cmd.Flags().StringSliceVar(&exposeUserGroups, "with-user-groups", nil, "")
	cmd.Flags().StringVar(&exposeDomain, "with-custom-domain", "", "")
	cmd.Flags().StringVar(&exposeNamePrefix, "with-name-prefix", "", "")
	cmd.Flags().StringVar(&exposeProtocol, "protocol", "http", "")
	cmd.Flags().Uint16Var(&exposeExternalPort, "with-external-port", 0, "")
	cmd.Flags().StringVar(&exposeTargetHost, "with-target-host", "", "")
	return cmd
}

func resetExposeFlagVars() {
	exposePin = ""
	exposePassword = ""
	exposeUserGroups = nil
	exposeDomain = ""
	exposeNamePrefix = ""
	exposeProtocol = "http"
	exposeExternalPort = 0
	exposeTargetHost = ""
}
