package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRuleString(t *testing.T) {
	tests := []struct {
		name      string
		rule      string
		protocol  PolicyRuleProtocolType
		portRange RulePortRange
		wantErr   bool
	}{
		{name: "all", rule: "all", protocol: PolicyRuleProtocolALL},
		{name: "icmp", rule: "icmp", protocol: PolicyRuleProtocolICMP},
		{name: "uppercase and padded", rule: "  ALL ", protocol: PolicyRuleProtocolALL},

		// The marker protocols imply their own port, so the bare spelling is
		// what the temporary-access flow sends.
		{
			name:      "bare netbird-ssh",
			rule:      "netbird-ssh",
			protocol:  PolicyRuleProtocolNetbirdSSH,
			portRange: RulePortRange{Start: nativeSSHPortNumber, End: nativeSSHPortNumber},
		},
		{
			name:      "bare netbird-vnc",
			rule:      "netbird-vnc",
			protocol:  PolicyRuleProtocolNetbirdVNC,
			portRange: RulePortRange{Start: VNCInternalPort, End: VNCInternalPort},
		},
		{
			name:      "netbird-vnc with an explicit port",
			rule:      "netbird-vnc/25900",
			protocol:  PolicyRuleProtocolNetbirdVNC,
			portRange: RulePortRange{Start: VNCInternalPort, End: VNCInternalPort},
		},

		{name: "tcp port", rule: "tcp/443", protocol: PolicyRuleProtocolTCP, portRange: RulePortRange{Start: 443, End: 443}},
		{name: "udp range", rule: "udp/5000-5010", protocol: PolicyRuleProtocolUDP, portRange: RulePortRange{Start: 5000, End: 5010}},

		{name: "icmp rejects a port", rule: "icmp/8", wantErr: true},
		{name: "unknown protocol", rule: "sctp/1", wantErr: true},
		{name: "no port", rule: "tcp", wantErr: true},
		{name: "empty port", rule: "tcp/", wantErr: true},
		{name: "port out of range", rule: "tcp/70000", wantErr: true},
		{name: "reversed range", rule: "tcp/500-400", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protocol, portRange, err := ParseRuleString(tt.rule)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.protocol, protocol)
			assert.Equal(t, tt.portRange, portRange)
		})
	}
}
