package crowdsec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/restrict"
)

func TestBouncer_CheckIP_Empty(t *testing.T) {
	b := newTestBouncer()
	b.ready.Store(true)

	assert.Nil(t, b.CheckIP(netip.MustParseAddr("1.2.3.4")))
}

func TestBouncer_CheckIP_ExactMatch(t *testing.T) {
	b := newTestBouncer()
	b.ready.Store(true)
	b.ips[netip.MustParseAddr("10.0.0.1")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}

	d := b.CheckIP(netip.MustParseAddr("10.0.0.1"))
	require.NotNil(t, d)
	assert.Equal(t, restrict.DecisionBan, d.Type)

	assert.Nil(t, b.CheckIP(netip.MustParseAddr("10.0.0.2")))
}

func TestBouncer_CheckIP_PrefixMatch(t *testing.T) {
	b := newTestBouncer()
	b.ready.Store(true)
	b.prefixes[netip.MustParsePrefix("192.168.1.0/24")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}

	d := b.CheckIP(netip.MustParseAddr("192.168.1.100"))
	require.NotNil(t, d)
	assert.Equal(t, restrict.DecisionBan, d.Type)

	assert.Nil(t, b.CheckIP(netip.MustParseAddr("192.168.2.1")))
}

func TestBouncer_CheckIP_UnmapsV4InV6(t *testing.T) {
	b := newTestBouncer()
	b.ready.Store(true)
	b.ips[netip.MustParseAddr("10.0.0.1")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}

	d := b.CheckIP(netip.MustParseAddr("::ffff:10.0.0.1"))
	require.NotNil(t, d)
	assert.Equal(t, restrict.DecisionBan, d.Type)
}

func TestBouncer_Ready(t *testing.T) {
	b := newTestBouncer()
	assert.False(t, b.Ready())

	b.ready.Store(true)
	assert.True(t, b.Ready())
}

func TestBouncer_CheckIP_ExactBeforePrefix(t *testing.T) {
	b := newTestBouncer()
	b.ready.Store(true)
	b.ips[netip.MustParseAddr("10.0.0.1")] = &restrict.CrowdSecDecision{Type: restrict.DecisionCaptcha}
	b.prefixes[netip.MustParsePrefix("10.0.0.0/8")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}

	d := b.CheckIP(netip.MustParseAddr("10.0.0.1"))
	require.NotNil(t, d)
	assert.Equal(t, restrict.DecisionCaptcha, d.Type)

	d2 := b.CheckIP(netip.MustParseAddr("10.0.0.2"))
	require.NotNil(t, d2)
	assert.Equal(t, restrict.DecisionBan, d2.Type)
}

func TestBouncer_ApplyNew_IP(t *testing.T) {
	b := newTestBouncer()

	b.applyNew(makeDecisions(
		decision{scope: "ip", value: "1.2.3.4", dtype: "ban", scenario: "test/brute"},
		decision{scope: "ip", value: "5.6.7.8", dtype: "captcha", scenario: "test/crawl"},
	))

	require.Len(t, b.ips, 2)
	assert.Equal(t, restrict.DecisionBan, b.ips[netip.MustParseAddr("1.2.3.4")].Type)
	assert.Equal(t, restrict.DecisionCaptcha, b.ips[netip.MustParseAddr("5.6.7.8")].Type)
}

func TestBouncer_ApplyNew_Range(t *testing.T) {
	b := newTestBouncer()

	b.applyNew(makeDecisions(
		decision{scope: "range", value: "10.0.0.0/8", dtype: "ban"},
	))

	require.Len(t, b.prefixes, 1)
	assert.NotNil(t, b.prefixes[netip.MustParsePrefix("10.0.0.0/8")])
}

func TestBouncer_ApplyDeleted_IP(t *testing.T) {
	b := newTestBouncer()
	b.ips[netip.MustParseAddr("1.2.3.4")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}
	b.ips[netip.MustParseAddr("5.6.7.8")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}

	b.applyDeleted(makeDecisions(
		decision{scope: "ip", value: "1.2.3.4", dtype: "ban"},
	))

	assert.Len(t, b.ips, 1)
	assert.Nil(t, b.ips[netip.MustParseAddr("1.2.3.4")])
	assert.NotNil(t, b.ips[netip.MustParseAddr("5.6.7.8")])
}

func TestBouncer_ApplyDeleted_Range(t *testing.T) {
	b := newTestBouncer()
	b.prefixes[netip.MustParsePrefix("10.0.0.0/8")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}
	b.prefixes[netip.MustParsePrefix("192.168.0.0/16")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}

	b.applyDeleted(makeDecisions(
		decision{scope: "range", value: "10.0.0.0/8", dtype: "ban"},
	))

	require.Len(t, b.prefixes, 1)
	assert.NotNil(t, b.prefixes[netip.MustParsePrefix("192.168.0.0/16")])
}

func TestBouncer_ApplyNew_OverwritesExisting(t *testing.T) {
	b := newTestBouncer()
	b.ips[netip.MustParseAddr("1.2.3.4")] = &restrict.CrowdSecDecision{Type: restrict.DecisionBan}

	b.applyNew(makeDecisions(
		decision{scope: "ip", value: "1.2.3.4", dtype: "captcha"},
	))

	assert.Equal(t, restrict.DecisionCaptcha, b.ips[netip.MustParseAddr("1.2.3.4")].Type)
}

func TestBouncer_ApplyNew_SkipsInvalid(t *testing.T) {
	b := newTestBouncer()

	b.applyNew(makeDecisions(
		decision{scope: "ip", value: "not-an-ip", dtype: "ban"},
		decision{scope: "range", value: "also-not-valid", dtype: "ban"},
	))

	assert.Empty(t, b.ips)
	assert.Empty(t, b.prefixes)
}

// TestBouncer_StreamIntegration tests the full flow: fake LAPI → StreamBouncer → Bouncer cache → CheckIP.
func TestBouncer_StreamIntegration(t *testing.T) {
	lapi := newFakeLAPI()
	ts := httptest.NewServer(lapi)
	defer ts.Close()

	// Seed the LAPI with initial decisions.
	lapi.setDecisions(
		decision{scope: "ip", value: "1.2.3.4", dtype: "ban", scenario: "crowdsecurity/ssh-bf"},
		decision{scope: "range", value: "10.0.0.0/8", dtype: "ban", scenario: "crowdsecurity/http-probing"},
		decision{scope: "ip", value: "5.5.5.5", dtype: "captcha", scenario: "crowdsecurity/http-crawl"},
	)

	b := NewBouncer(ts.URL, "test-key", log.NewEntry(log.StandardLogger()))
	b.tickerInterval = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, b.Start(ctx))
	defer b.Stop()

	// Wait for initial sync.
	require.Eventually(t, b.Ready, 5*time.Second, 50*time.Millisecond, "bouncer should become ready")

	// Verify decisions are cached.
	d := b.CheckIP(netip.MustParseAddr("1.2.3.4"))
	require.NotNil(t, d, "1.2.3.4 should be banned")
	assert.Equal(t, restrict.DecisionBan, d.Type)

	d2 := b.CheckIP(netip.MustParseAddr("10.1.2.3"))
	require.NotNil(t, d2, "10.1.2.3 should match range ban")
	assert.Equal(t, restrict.DecisionBan, d2.Type)

	d3 := b.CheckIP(netip.MustParseAddr("5.5.5.5"))
	require.NotNil(t, d3, "5.5.5.5 should have captcha")
	assert.Equal(t, restrict.DecisionCaptcha, d3.Type)

	assert.Nil(t, b.CheckIP(netip.MustParseAddr("9.9.9.9")), "unknown IP should be nil")

	// Simulate a delta update: delete one IP, add a new one.
	lapi.setDelta(
		[]decision{{scope: "ip", value: "1.2.3.4", dtype: "ban"}},
		[]decision{{scope: "ip", value: "2.3.4.5", dtype: "throttle", scenario: "crowdsecurity/http-flood"}},
	)

	// Wait for the delta to be picked up.
	require.Eventually(t, func() bool {
		return b.CheckIP(netip.MustParseAddr("2.3.4.5")) != nil
	}, 5*time.Second, 50*time.Millisecond, "new decision should appear")

	assert.Nil(t, b.CheckIP(netip.MustParseAddr("1.2.3.4")), "deleted decision should be gone")

	d4 := b.CheckIP(netip.MustParseAddr("2.3.4.5"))
	require.NotNil(t, d4)
	assert.Equal(t, restrict.DecisionThrottle, d4.Type)

	// Range ban should still be active.
	assert.NotNil(t, b.CheckIP(netip.MustParseAddr("10.99.99.99")))
}

// Helpers

func newTestBouncer() *Bouncer {
	return &Bouncer{
		ips:      make(map[netip.Addr]*restrict.CrowdSecDecision),
		prefixes: make(map[netip.Prefix]*restrict.CrowdSecDecision),
		logger:   log.NewEntry(log.StandardLogger()),
	}
}

type decision struct {
	scope    string
	value    string
	dtype    string
	scenario string
}

func makeDecisions(decs ...decision) []*models.Decision {
	out := make([]*models.Decision, len(decs))
	for i, d := range decs {
		out[i] = &models.Decision{
			Scope:    strPtr(d.scope),
			Value:    strPtr(d.value),
			Type:     strPtr(d.dtype),
			Scenario: strPtr(d.scenario),
			Duration: strPtr("1h"),
			Origin:   strPtr("cscli"),
		}
	}
	return out
}

func strPtr(s string) *string { return &s }

// fakeLAPI is a minimal fake CrowdSec LAPI that serves /v1/decisions/stream.
type fakeLAPI struct {
	mu       sync.Mutex
	initial  []decision
	newDelta []decision
	delDelta []decision
	served   bool // true after the initial snapshot has been served
}

func newFakeLAPI() *fakeLAPI {
	return &fakeLAPI{}
}

func (f *fakeLAPI) setDecisions(decs ...decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initial = decs
	f.served = false
}

func (f *fakeLAPI) setDelta(deleted, added []decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delDelta = deleted
	f.newDelta = added
}

func (f *fakeLAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/decisions/stream" {
		http.NotFound(w, r)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	resp := streamResponse{}

	if !f.served {
		for _, d := range f.initial {
			resp.New = append(resp.New, toLAPIDecision(d))
		}
		f.served = true
	} else {
		for _, d := range f.delDelta {
			resp.Deleted = append(resp.Deleted, toLAPIDecision(d))
		}
		for _, d := range f.newDelta {
			resp.New = append(resp.New, toLAPIDecision(d))
		}
		// Clear delta after serving once.
		f.delDelta = nil
		f.newDelta = nil
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// streamResponse mirrors the CrowdSec LAPI /v1/decisions/stream JSON structure.
type streamResponse struct {
	New     []*lapiDecision `json:"new"`
	Deleted []*lapiDecision `json:"deleted"`
}

type lapiDecision struct {
	Duration *string `json:"duration"`
	Origin   *string `json:"origin"`
	Scenario *string `json:"scenario"`
	Scope    *string `json:"scope"`
	Type     *string `json:"type"`
	Value    *string `json:"value"`
}

func toLAPIDecision(d decision) *lapiDecision {
	return &lapiDecision{
		Duration: strPtr("1h"),
		Origin:   strPtr("cscli"),
		Scenario: strPtr(d.scenario),
		Scope:    strPtr(d.scope),
		Type:     strPtr(d.dtype),
		Value:    strPtr(d.value),
	}
}
