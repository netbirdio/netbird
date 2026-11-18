package status

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

func alignedStatus(now time.Time) *proto.FullStatus {
	clamped := &proto.AlignedHeartbeatCorrection{
		Service: "signal", Address: "https://signal.example.com:443", Time: timestamppb.New(now.Add(-time.Minute)),
		OffsetMillis: 3000, FromPhaseMillis: 5000, WantedPhaseMillis: 2000, Result: "ignored",
	}
	return &proto.FullStatus{
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
		LocalPeerState:  &proto.LocalPeerState{},
		AlignedHeartbeat: &proto.AlignedHeartbeatState{
			Streams: []*proto.AlignedHeartbeatStream{
				{Service: "management", Address: "https://api.example.com:443", Level: "aligned",
					PeriodSeconds: 60, PhaseMillis: 12345, LastHeartbeat: timestamppb.New(now.Add(-20 * time.Second))},
				{Service: "signal", Address: "https://signal.example.com:443", Level: "aligned",
					PeriodSeconds: 60, PhaseMillis: 5000, LastHeartbeat: timestamppb.New(now.Add(-20 * time.Second)),
					LastCorrection: clamped, CorrectionBlocked: true, BlockedInRow: 3, ClampHits: 4},
				{Service: "relay", Address: "rels://relay.example.com:443", Level: "stock"},
			},
			Corrections: []*proto.AlignedHeartbeatCorrection{clamped},
		},
	}
}

func TestAlignedHeartbeatSummary(t *testing.T) {
	now := time.Now()
	overview := ConvertToStatusOutputOverview(alignedStatus(now), ConvertOptions{})
	summary := overview.GeneralSummary(true, true, true, true)

	assert.Contains(t, summary, "Aligned heartbeat:\n", "section header")
	assert.Contains(t, summary,
		"  Management [https://api.example.com:443]: aligned, period 60s, phase 12345 ms, last heartbeat 20 seconds ago\n",
		"management line has no correction")
	assert.Contains(t, summary,
		"  Signal [https://signal.example.com:443]: aligned, period 60s, phase 5000 ms, last heartbeat 20 seconds ago, "+
			"last correction 1 minute ago: phase 5000 ms to 2000 ms, ignored, "+
			"corrections blocked: 3 in a row not applied by the server, its clock may be off\n",
		"signal line with the blocked correction")
	assert.Contains(t, summary, "  Relay [rels://relay.example.com:443]: stock, last correction none\n", "stock relay")
	assert.NotContains(t, summary, "Aligned heartbeat corrections:", "history only in the detail")
}

func TestAlignedHeartbeatDetail(t *testing.T) {
	now := time.Now()
	overview := ConvertToStatusOutputOverview(alignedStatus(now), ConvertOptions{})
	detail := overview.FullDetailSummary()

	at := now.Add(-time.Minute).UTC().Format(time.RFC3339)
	assert.Contains(t, detail, "Aligned heartbeat corrections:\n  "+at+
		" Signal [https://signal.example.com:443]: offset 3000 ms, phase 5000 ms to 2000 ms, ignored\n", "history")
	assert.Contains(t, detail, "Aligned heartbeat clamp hits:\n"+
		"  Signal [https://signal.example.com:443]: 4, 3 in a row\n"+
		"  Relay [rels://relay.example.com:443]: 0, 0 in a row\n", "clamp hits per stream, none for management")
	assert.Contains(t, detail, "Aligned heartbeat:\n", "stream lines too")
}

// A client that does not ask for the aligned heartbeat prints nothing new.
func TestAlignedHeartbeatAbsent(t *testing.T) {
	overview := ConvertToStatusOutputOverview(&proto.FullStatus{
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
		LocalPeerState:  &proto.LocalPeerState{},
	}, ConvertOptions{})
	assert.Nil(t, overview.AlignedHeartbeat, "no state")
	assert.NotContains(t, overview.FullDetailSummary(), "Aligned heartbeat", "no section")

	js, err := overview.JSON()
	require.NoError(t, err)
	assert.NotContains(t, js, "alignedHeartbeat", "omitted from JSON")
}

func TestAlignedHeartbeatJSONAndAnonymize(t *testing.T) {
	overview := ConvertToStatusOutputOverview(alignedStatus(time.Now()), ConvertOptions{})
	js, err := overview.JSON()
	require.NoError(t, err)
	assert.Contains(t, js, `"alignedHeartbeat"`, "in JSON")
	assert.Contains(t, js, `"clampHits":4`, "clamp hits in JSON")

	anon := ConvertToStatusOutputOverview(alignedStatus(time.Now()), ConvertOptions{Anonymize: true})
	detail := anon.FullDetailSummary()
	for _, host := range []string{"api.example.com", "signal.example.com", "relay.example.com"} {
		assert.False(t, strings.Contains(detail, host), "%s anonymized", host)
	}
	require.Len(t, anon.AlignedHeartbeat.Streams, 3)
	assert.NotEmpty(t, anon.AlignedHeartbeat.Streams[1].Address, "address replaced, not dropped")
	assert.Equal(t, anon.AlignedHeartbeat.Streams[1].Address, anon.AlignedHeartbeat.Corrections[0].Address,
		"same server, same anonymized address")
}

// Management and Signal report their stream address as host:port without a
// scheme. Every address in the section must be anonymized with the mapping the
// rest of the status uses for the same host, whatever form it has.
func TestAlignedHeartbeatAnonymizeAddressForms(t *testing.T) {
	const host = "34-136-32-63.sslip.io"
	now := time.Now()
	correction := &proto.AlignedHeartbeatCorrection{
		Service: "signal", Address: host + ":443", Time: timestamppb.New(now.Add(-time.Minute)),
		OffsetMillis: 1000, FromPhaseMillis: 5000, WantedPhaseMillis: 4000, Result: "applied",
	}
	full := &proto.FullStatus{
		ManagementState: &proto.ManagementState{URL: "https://" + host + ":443", Connected: true},
		SignalState:     &proto.SignalState{URL: "https://" + host + ":443", Connected: true},
		LocalPeerState:  &proto.LocalPeerState{},
		AlignedHeartbeat: &proto.AlignedHeartbeatState{
			Streams: []*proto.AlignedHeartbeatStream{
				{Service: "management", Address: host + ":443", Level: "aligned", PeriodSeconds: 60},
				{Service: "signal", Address: host + ":443", Level: "aligned", PeriodSeconds: 60,
					LastCorrection: correction},
				{Service: "relay", Address: "rels://" + host + ":443", Level: "aligned", PeriodSeconds: 60},
				{Service: "relay", Address: "34.136.32.63:443", Level: "stock"},
				{Service: "relay", Address: "[2a00:1450:4001::1]:443", Level: "stock"},
				{Service: "relay", Address: "rels://34.136.32.63:443", Level: "stock"},
				{Service: "relay", Address: "rels://[2a00:1450:4001::1]:443", Level: "stock"},
				{Service: "relay", Address: host, Level: "stock"},
				{Service: "relay", Address: "34.136.32.63", Level: "stock"},
				{Service: "relay", Address: "[2a00:1450:4001::1]", Level: "stock"},
			},
			Corrections: []*proto.AlignedHeartbeatCorrection{correction},
		},
	}

	anon := ConvertToStatusOutputOverview(full, ConvertOptions{Anonymize: true})
	detail := anon.FullDetailSummary()
	for _, raw := range []string{host, "34.136.32.63", "34.136.", "2a00:1450"} {
		assert.NotContains(t, detail, raw, "%s must not appear in the anonymized status", raw)
	}

	anonHost := strings.TrimSuffix(strings.TrimPrefix(anon.ManagementState.URL, "https://"), ":443")
	require.NotEqual(t, host, anonHost, "management URL is anonymized")

	streams := anon.AlignedHeartbeat.Streams
	require.Len(t, streams, 10)
	assert.Equal(t, anonHost+":443", streams[0].Address, "management host:port uses the status mapping")
	assert.Equal(t, anonHost+":443", streams[1].Address, "signal host:port uses the status mapping")
	assert.Equal(t, anon.ManagementState.URL, "https://"+streams[1].Address, "same host as the Management line")
	assert.Equal(t, "rels://"+anonHost+":443", streams[2].Address, "relay URI uses the status mapping")
	assert.Equal(t, anonHost+":443", streams[1].LastCorrection.Address, "last correction anonymized")
	assert.Equal(t, anonHost+":443", anon.AlignedHeartbeat.Corrections[0].Address, "correction history anonymized")
	assert.Equal(t, anonHost, streams[7].Address, "bare host uses the status mapping")

	anonV4 := anon.AlignedHeartbeat.Streams[8].Address
	assert.Equal(t, anonV4+":443", streams[3].Address, "IPv4 host:port keeps the port")
	assert.Equal(t, "rels://"+anonV4+":443", streams[5].Address, "IPv4 in a URI uses the same mapping")
	assert.Regexp(t, `^\[[0-9a-f:]+\]:443$`, streams[4].Address, "IPv6 host:port keeps brackets and port")
	assert.Regexp(t, `^rels://\[[0-9a-f:]+\]:443$`, streams[6].Address, "IPv6 in a URI keeps brackets and port")
	assert.Regexp(t, `^\[[0-9a-f:]+\]$`, streams[9].Address, "bracketed IPv6 keeps brackets")
	assert.Equal(t, strings.TrimSuffix(streams[4].Address, ":443"), streams[9].Address, "same IPv6 mapping")
}
