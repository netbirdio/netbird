package config

import (
	"sort"
	"testing"
)

func TestRelay_HasURLs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		r    *Relay
		want bool
	}{
		{name: "nil", r: nil, want: false},
		{name: "empty", r: &Relay{}, want: false},
		{name: "addresses only", r: &Relay{Addresses: []string{"rels://a"}}, want: true},
		{name: "endpoints only", r: &Relay{Endpoints: []RelayEndpoint{{URL: "rels://a"}}}, want: true},
		{name: "endpoint with empty url", r: &Relay{Endpoints: []RelayEndpoint{{URL: ""}}}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.HasURLs(); got != tc.want {
				t.Fatalf("HasURLs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRelay_AllURLs_dedupes_and_preserves_order(t *testing.T) {
	t.Parallel()
	r := &Relay{
		Addresses: []string{"rels://shared", "rels://addr-only"},
		Endpoints: []RelayEndpoint{
			{URL: "rels://ep-only"},
			{URL: "rels://shared"}, // also in Addresses; should not double up
			{URL: ""},              // skipped
		},
	}
	got := r.AllURLs()
	want := []string{"rels://ep-only", "rels://shared", "rels://addr-only"}
	if len(got) != len(want) {
		t.Fatalf("AllURLs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllURLs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRelay_Normalize_drops_unknown_transports_and_dupes(t *testing.T) {
	t.Parallel()
	r := &Relay{
		Endpoints: []RelayEndpoint{
			{URL: "rels://a", Transports: []string{"ws", "ws", "wt", "bogus", "h2"}},
			{URL: "rels://b", Transports: []string{"quic", "wt"}},
			{URL: "rels://a", Transports: []string{"ws"}}, // duplicate URL — dropped
			{URL: ""},                                     // empty URL — dropped
		},
	}
	unknown := r.Normalize()

	// Unknown transports should be reported (order not specified).
	sort.Strings(unknown)
	wantUnknown := []string{"bogus", "h2"}
	if len(unknown) != len(wantUnknown) {
		t.Fatalf("unknown = %v, want %v", unknown, wantUnknown)
	}
	for i := range wantUnknown {
		if unknown[i] != wantUnknown[i] {
			t.Fatalf("unknown[%d] = %q, want %q", i, unknown[i], wantUnknown[i])
		}
	}

	if len(r.Endpoints) != 2 {
		t.Fatalf("endpoints after Normalize = %d, want 2: %#v", len(r.Endpoints), r.Endpoints)
	}
	if r.Endpoints[0].URL != "rels://a" || len(r.Endpoints[0].Transports) != 2 ||
		r.Endpoints[0].Transports[0] != "ws" || r.Endpoints[0].Transports[1] != "wt" {
		t.Fatalf("endpoint a after Normalize = %#v", r.Endpoints[0])
	}
	if r.Endpoints[1].URL != "rels://b" || len(r.Endpoints[1].Transports) != 2 {
		t.Fatalf("endpoint b after Normalize = %#v", r.Endpoints[1])
	}
}

func TestRelay_Normalize_keeps_empty_transports(t *testing.T) {
	t.Parallel()
	// An empty Transports list is "unknown — try every dialer", which is a
	// valid signal we must preserve (distinct from "I typoed all entries").
	r := &Relay{Endpoints: []RelayEndpoint{{URL: "rels://a"}}}
	if u := r.Normalize(); len(u) != 0 {
		t.Fatalf("Normalize reported unknown transports on empty list: %v", u)
	}
	if len(r.Endpoints) != 1 || len(r.Endpoints[0].Transports) != 0 {
		t.Fatalf("endpoint mutated: %#v", r.Endpoints)
	}
}
