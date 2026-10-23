package status

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protobuf "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/proto"
)

func TestPeersTable(t *testing.T) {
	overview := OutputOverview{Peers: PeersStateOutput{
		Total:     2,
		Connected: 1,
		Details: []PeerStateDetailOutput{
			{
				FQDN:             "web-01.netbird.cloud",
				IP:               "100.64.0.12",
				PubKey:           "k3Vx9pQ2abcdefghijklmnopqrstuvwxyz0123456789=",
				Status:           "Connected",
				ConnType:         "P2P",
				Latency:          12 * time.Millisecond,
				TransferReceived: 1024,
				TransferSent:     2048,
			},
			{
				FQDN:   "old-nas.netbird.cloud",
				IP:     "100.64.0.77",
				Status: "Idle",
			},
		},
	}}

	lines := strings.Split(strings.TrimRight(overview.PeersTable(), "\n"), "\n")
	require.Len(t, lines, 4, "title, header and one line per peer")

	assert.Equal(t, "Peers (1/2 connected):", lines[0])
	assert.Equal(t,
		[]string{"NAME", "IP", "STATUS", "CONN", "LATENCY", "RX", "/", "TX"},
		strings.Fields(lines[1]))

	connected := strings.Fields(lines[2])
	assert.Equal(t, "web-01", connected[0], "domain suffix must be dropped")
	assert.Equal(t, "Connected", connected[2])
	assert.Equal(t, "P2P", connected[3])
	assert.Equal(t, "12ms", connected[4])
	assert.NotContains(t, lines[2], "k3Vx9pQ2", "public key must not be shown")
	assert.Contains(t, lines[2], "1.0 KiB / 2.0 KiB")

	idle := strings.Fields(lines[3])
	assert.Equal(t, []string{"old-nas", "100.64.0.77", "Idle", "-", "-", "0", "B", "/", "0", "B"}, idle,
		"missing values render as dashes")
}

func TestPeersTable_NoPeers(t *testing.T) {
	out := (&OutputOverview{}).PeersTable()
	assert.True(t, strings.HasPrefix(out, "Peers (0/0 connected):\n"))
	assert.Contains(t, out, "NAME")
}

func tableRows(t *testing.T, opts ConvertOptions) []string {
	t.Helper()

	opts.DaemonVersion = resp.GetDaemonVersion()
	opts.DaemonStatus = ParseDaemonStatus(resp.GetStatus())
	// The anonymizer rewrites slices in place, so work on a copy to keep the
	// shared fixture intact for the other tests.
	fullStatus := protobuf.Clone(resp.GetFullStatus()).(*proto.FullStatus)
	overview := ConvertToStatusOutputOverview(fullStatus, opts)
	out := overview.PeersTable()

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 2, "title and header are always present")
	return lines
}

// The fixture holds peer-1 (connected, P2P) and peer-2 (connected, relayed).
func TestPeersTable_Filters(t *testing.T) {
	tests := []struct {
		name      string
		opts      ConvertOptions
		wantTitle string
		wantPeers []string
	}{
		{
			name:      "no filter lists every peer sorted by IP",
			wantTitle: "Peers (2/2 connected):",
			wantPeers: []string{"peer-1", "peer-2"},
		},
		{
			name:      "connection type P2P",
			opts:      ConvertOptions{ConnectionTypeFilter: "P2P"},
			wantTitle: "Peers (1/1 connected):",
			wantPeers: []string{"peer-1"},
		},
		{
			name:      "connection type Relayed",
			opts:      ConvertOptions{ConnectionTypeFilter: "relayed"},
			wantTitle: "Peers (1/1 connected):",
			wantPeers: []string{"peer-2"},
		},
		{
			name:      "status with no match",
			opts:      ConvertOptions{StatusFilter: "idle"},
			wantTitle: "Peers (0/0 connected):",
		},
		{
			name: "name prefix",
			opts: ConvertOptions{
				PrefixNamesFilter:    []string{"peer-2"},
				PrefixNamesFilterMap: map[string]struct{}{"peer-2": {}},
			},
			wantTitle: "Peers (1/1 connected):",
			wantPeers: []string{"peer-2"},
		},
		{
			name:      "IPv4",
			opts:      ConvertOptions{IPsFilter: map[string]struct{}{"192.168.178.101": {}}},
			wantTitle: "Peers (1/1 connected):",
			wantPeers: []string{"peer-1"},
		},
		{
			name:      "IPv6",
			opts:      ConvertOptions{IPsFilter: map[string]struct{}{"fd00::1": {}}},
			wantTitle: "Peers (1/1 connected):",
			wantPeers: []string{"peer-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := tableRows(t, tt.opts)

			assert.Equal(t, tt.wantTitle, lines[0])
			rows := lines[2:]
			require.Len(t, rows, len(tt.wantPeers), "one row per matching peer")
			for i, name := range tt.wantPeers {
				assert.True(t, strings.HasPrefix(rows[i], name+" "), "row %d should be %s, got %q", i, name, rows[i])
			}
		})
	}
}

// The table shows whatever the anonymizer left in the overview, so it must
// carry the redacted names rather than the originals.
func TestPeersTable_Anonymized(t *testing.T) {
	lines := tableRows(t, ConvertOptions{Anonymize: true, AnonymizeLevel: anonymize.LevelStrict})

	for _, row := range lines[2:] {
		assert.NotContains(t, row, "awesome-domain.com", "FQDN must be anonymized")
		assert.NotContains(t, row, "peer-", "peer name must be anonymized")
	}
}

func TestShortName(t *testing.T) {
	assert.Equal(t, "web-01", shortName("web-01.netbird.cloud"))
	assert.Equal(t, "web-01", shortName("web-01"))
	assert.Equal(t, "-", shortName(""))
}

func TestTableLatency(t *testing.T) {
	tests := map[time.Duration]string{
		0:                           "-",
		145939625 * time.Nanosecond: "146ms",
		12 * time.Millisecond:       "12ms",
		420*time.Microsecond + 700:  "421µs",
	}
	for in, want := range tests {
		assert.Equal(t, want, tableLatency(PeerStateDetailOutput{Latency: in}), "latency %s", in)
	}
}

// peer-1 is what a fresh strict anonymizer would hand out first, so a peer
// with that exact name must still be replaced in the table.
func TestPeersTable_AnonymizedPeerNamedLikePlaceholder(t *testing.T) {
	fullStatus := &proto.FullStatus{
		Peers: []*proto.PeerState{
			{Fqdn: "peer-1.netbird.cloud", IP: "100.64.0.1", ConnStatus: "Idle"},
		},
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
	}
	overview := ConvertToStatusOutputOverview(fullStatus, ConvertOptions{
		Anonymize:      true,
		AnonymizeLevel: anonymize.LevelStrict,
	})

	lines := strings.Split(strings.TrimRight(overview.PeersTable(), "\n"), "\n")
	require.Len(t, lines, 3, "title, header and one peer row")
	assert.NotEqual(t, "peer-1", strings.Fields(lines[2])[0], "the original name must not be shown")
}
