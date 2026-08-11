package types

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// etagSettings is a fully populated settings row — every hashed field set to a
// distinctive value — so a mutation test can flip exactly one thing at a time.
func etagSettings() *Settings {
	created := time.Date(2026, 8, 11, 9, 30, 0, 0, time.UTC)
	return &Settings{
		AccountID:              "acc-1",
		Domain:                 "cool-otter.eu.proxy.netbird.io",
		ProxyAddress:           "eu.proxy.netbird.io",
		EnableLogCollection:    true,
		EnablePromptCollection: true,
		RedactPii:              true,
		AccessLogRetentionDays: 30,
		CreatedAt:              created,
		UpdatedAt:              created,
	}
}

// TestSettings_ETagShape pins the wire shape of the validator: a bare
// lowercase hex string of the documented length, with no quoting — quoting is
// the transport layer's job, and a validator that arrived pre-quoted would be
// double-quoted on the way out.
func TestSettings_ETagShape(t *testing.T) {
	etag := etagSettings().ETag()

	assert.Len(t, etag, etagLength, "the validator must be exactly etagLength characters")
	assert.NotContains(t, etag, `"`, "the derived validator must not carry its own quoting")
	for _, r := range etag {
		require.Truef(t, (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'),
			"the validator must be lowercase hex, got %q in %q", r, etag)
	}
}

// TestSettings_ETagIsStable covers the guarantee every conditional request
// rests on: an unchanged row derives the same validator every time, including
// across a fresh struct built from the same values. A validator that varied
// per derivation would fail every If-Match and make the feature unusable.
func TestSettings_ETagIsStable(t *testing.T) {
	s := etagSettings()

	first := s.ETag()
	assert.Equal(t, first, s.ETag(), "repeated derivation from one value must agree")
	assert.Equal(t, first, etagSettings().ETag(), "an equal row must derive an equal validator")
}

// TestSettings_ETagSensitivity is the other half of the contract: every field
// the validator covers must actually move it. The cases are also what makes
// the field-count guard meaningful — a new field that belongs in the tuple but
// is missing from it has no case here, and the guard is what catches that.
//
// The mutations are checked to be pairwise distinct, not merely different from
// the baseline: that is what catches an ambiguous concatenation, where moving
// a character across a field boundary would hash identically without the
// delimiter.
func TestSettings_ETagSensitivity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Settings)
	}{
		{"domain", func(s *Settings) { s.Domain = "brave-otter.eu.proxy.netbird.io" }},
		{"proxy address", func(s *Settings) { s.ProxyAddress = "us.proxy.netbird.io" }},
		{"log collection", func(s *Settings) { s.EnableLogCollection = false }},
		{"prompt collection", func(s *Settings) { s.EnablePromptCollection = false }},
		{"redact pii", func(s *Settings) { s.RedactPii = false }},
		{"retention", func(s *Settings) { s.AccessLogRetentionDays = 14 }},
		{"created at", func(s *Settings) { s.CreatedAt = s.CreatedAt.Add(time.Nanosecond) }},
		// Moving characters across the Domain/ProxyAddress boundary leaves
		// the two fields' concatenation byte-identical, so this case passes
		// only because the tuple is delimited.
		{"identity boundary shifted", func(s *Settings) {
			joined := s.Domain + s.ProxyAddress
			split := len(s.Domain) - 3
			s.Domain, s.ProxyAddress = joined[:split], joined[split:]
		}},
	}

	baseline := etagSettings().ETag()
	seen := map[string]string{"baseline": baseline}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := etagSettings()
			tc.mutate(s)

			etag := s.ETag()
			assert.NotEqual(t, baseline, etag, "changing %s must change the validator", tc.name)

			if other, clash := seen[etag]; clash {
				t.Fatalf("changing %s derives the same validator as %s (%s) — the field tuple is ambiguous", tc.name, other, etag)
			}
			seen[etag] = tc.name
		})
	}
}

// TestSettings_ETagExclusions pins the two deliberate omissions. AccountID is
// the resource's identity rather than its representation. UpdatedAt is left
// out so that a write which changes nothing observable does not invalidate a
// precondition another client is holding — equal representations must always
// derive equal validators.
func TestSettings_ETagExclusions(t *testing.T) {
	baseline := etagSettings().ETag()

	other := etagSettings()
	other.AccountID = "acc-2"
	assert.Equal(t, baseline, other.ETag(), "the account id must not reach the validator")

	touched := etagSettings()
	touched.UpdatedAt = touched.UpdatedAt.Add(time.Hour)
	assert.Equal(t, baseline, touched.ETag(), "a write that changed nothing must not move the validator")
}

// TestSettings_ETagOfDefaults covers the pre-bootstrap view, which GET serves
// as a real representation and therefore validates like one. It must derive
// without panicking on the zero CreatedAt, and it must not collide with a
// bootstrapped row — otherwise an If-Match taken before bootstrap would
// authorize a write against the row that appeared since.
func TestSettings_ETagOfDefaults(t *testing.T) {
	defaults := DefaultSettings("acc-1").ETag()

	assert.Len(t, defaults, etagLength, "the default view must derive a well-formed validator")
	assert.NotEqual(t, etagSettings().ETag(), defaults,
		"the unbootstrapped view must not validate as a bootstrapped row")
}

// etagFieldCount is the number of fields Settings carries. ETag hashes an
// explicit tuple rather than the struct, so a field added here is silently
// outside the validator until someone decides otherwise — the worst kind of
// gap, because the mechanism looks present and works for every other field.
//
// If this constant needs updating, that is the decision point: either add the
// new field to ETag and give it a case in TestSettings_ETagSensitivity, or
// record here why it stays out.
const etagFieldCount = 9

// TestSettings_ETagFieldCountGuard fails when a field is added to or removed
// from Settings, forcing the question of whether it belongs in the validator.
func TestSettings_ETagFieldCountGuard(t *testing.T) {
	assert.Equal(t, etagFieldCount, reflect.TypeFor[Settings]().NumField(),
		"Settings gained or lost a field: decide whether it belongs in ETag(), then update etagFieldCount")
}
