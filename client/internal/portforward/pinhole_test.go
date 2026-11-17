//go:build !js

package portforward

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/netbirdio/go-nat"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPinholeNAT is a gateway that also reports an IPv6 pinhole outcome, the
// shape a dual-stack gateway has.
type mockPinholeNAT struct {
	*mockNAT
	pinholeErr error
}

func (m *mockPinholeNAT) IPv6PinholeError() error {
	return m.pinholeErr
}

func TestSetupLogsPinholeOutcome(t *testing.T) {
	pinholeErr := errors.New("pcp ipv6: NOT_AUTHORIZED")

	tests := []struct {
		name       string
		pinholeErr error
		mappingErr error
		wantLevel  log.Level
		wantText   string
	}{
		{
			name:      "an open pinhole is reported",
			wantLevel: log.InfoLevel,
			wantText:  "IPv6 pinhole open",
		},
		{
			name: "a failed pinhole is reported without failing the mapping",
			// The IPv4 mapping is what the caller asked for, so the pinhole
			// failure surfaces only in the log.
			pinholeErr: pinholeErr,
			wantLevel:  log.WarnLevel,
			wantText:   pinholeErr.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway := &mockPinholeNAT{mockNAT: newMockNAT(), pinholeErr: tt.pinholeErr}
			hook := stubGatewayDiscovery(t, gateway)

			m := NewManager()
			m.wgPort = 51820

			_, mapping, err := m.setup(context.Background())

			require.NoError(t, err)
			require.NotNil(t, mapping)

			entry := findEntry(hook, tt.wantText)
			require.NotNil(t, entry, "no log entry mentioning %q", tt.wantText)
			assert.Equal(t, tt.wantLevel, entry.Level)
		})
	}

	t.Run("a failed mapping reports no pinhole outcome", func(t *testing.T) {
		// Nothing opened the pinhole, so whatever it currently reports says
		// nothing about this attempt.
		gateway := &mockPinholeNAT{mockNAT: newMockNAT()}
		gateway.addMappingErr = errors.New("gateway refused")
		hook := stubGatewayDiscovery(t, gateway)

		m := NewManager()
		m.wgPort = 51820

		_, _, err := m.setup(context.Background())

		require.Error(t, err)
		assert.Nil(t, findEntry(hook, "IPv6 pinhole"))
	})
}

// stubGatewayDiscovery makes discovery return gateway and captures log output.
func stubGatewayDiscovery(t *testing.T, gateway nat.NAT) *test.Hook {
	t.Helper()

	orig := discoverGateway
	discoverGateway = func(context.Context) (nat.NAT, error) { return gateway, nil }
	t.Cleanup(func() { discoverGateway = orig })

	hook := test.NewGlobal()
	origLevel := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		hook.Reset()
		log.SetLevel(origLevel)
	})

	return hook
}

func findEntry(hook *test.Hook, substr string) *log.Entry {
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, substr) {
			return entry
		}
	}
	return nil
}
