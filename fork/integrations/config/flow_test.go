// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setRequiredFlowEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvFlowGroups, "grp-flow-a, grp-flow-b")
	t.Setenv(EnvFlowReceiverURL, "flows.example.com:443")
	t.Setenv(EnvFlowSigningKey, "s3cr3t")
}

func clearFlowEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvFlowGroups, EnvFlowReceiverURL, EnvFlowSigningKey,
		EnvFlowInterval, EnvFlowDNSCollection, EnvFlowExitNodeCollection,
	} {
		t.Setenv(name, "")
	}
}

func TestReadFlowSettings_DisabledWhenRequiredMissing(t *testing.T) {
	clearFlowEnv(t)

	settings := readFlowSettings()

	assert.False(t, settings.Enabled, "collection must stay off without all three required env vars")
	assert.Empty(t, settings.Groups)
	assert.Empty(t, settings.ReceiverURL)
	assert.Empty(t, settings.TokenSecret)
}

func TestReadFlowSettings_DisabledWithPartialEnv(t *testing.T) {
	clearFlowEnv(t)
	t.Setenv(EnvFlowGroups, "grp-flow-a")
	t.Setenv(EnvFlowReceiverURL, "flows.example.com:443")

	settings := readFlowSettings()

	assert.False(t, settings.Enabled, "one missing required env var must disable the whole pipeline")
	assert.Equal(t, []string{"grp-flow-a"}, settings.Groups, "parsed values are kept for diagnostics even when disabled")
}

func TestReadFlowSettings_EnabledWithDefaults(t *testing.T) {
	clearFlowEnv(t)
	setRequiredFlowEnv(t)

	settings := readFlowSettings()

	assert.True(t, settings.Enabled)
	assert.Equal(t, []string{"grp-flow-a", "grp-flow-b"}, settings.Groups)
	assert.Equal(t, "flows.example.com:443", settings.ReceiverURL)
	assert.Equal(t, "s3cr3t", settings.TokenSecret)
	assert.Equal(t, defaultFlowInterval, settings.Interval, "unset interval must fall back to the default")
	assert.False(t, settings.DNSCollection)
	assert.False(t, settings.ExitNodeCollection)
}

func TestReadFlowSettings_ParsesOptionalEnv(t *testing.T) {
	clearFlowEnv(t)
	setRequiredFlowEnv(t)
	t.Setenv(EnvFlowInterval, "30s")
	t.Setenv(EnvFlowDNSCollection, "true")
	t.Setenv(EnvFlowExitNodeCollection, "1")

	settings := readFlowSettings()

	assert.Equal(t, 30*time.Second, settings.Interval)
	assert.True(t, settings.DNSCollection)
	assert.True(t, settings.ExitNodeCollection)
}

func TestParseFlowInterval(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected time.Duration
	}{
		{"empty falls back", "", defaultFlowInterval},
		{"valid duration", "90s", 90 * time.Second},
		{"invalid falls back", "not-a-duration", defaultFlowInterval},
		{"negative falls back", "-5s", defaultFlowInterval},
		{"zero falls back", "0s", defaultFlowInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseFlowInterval(tt.raw))
		})
	}
}

func TestParseBoolEnv(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		set      bool
		expected bool
	}{
		{"unset is false", "", false, false},
		{"true", "true", true, true},
		{"numeric true", "1", true, true},
		{"garbage is false", "banana", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(EnvFlowDNSCollection, tt.value)
			} else {
				t.Setenv(EnvFlowDNSCollection, "")
			}
			assert.Equal(t, tt.expected, parseBoolEnv(EnvFlowDNSCollection))
		})
	}
}

func TestParseGroupIDs(t *testing.T) {
	assert.Empty(t, parseGroupIDs(""), "empty input yields no groups")
	assert.Equal(t, []string{"a"}, parseGroupIDs("a"))
	assert.Equal(t, []string{"a", "b", "c"}, parseGroupIDs(" a ,b,, c"),
		"whitespace is trimmed and empty items are dropped")
}

func TestMatchesAnyGroup(t *testing.T) {
	settings := FlowSettings{Groups: []string{"g1", "g2"}}

	assert.False(t, settings.matchesAnyGroup(nil), "no peer groups never matches")
	assert.False(t, settings.matchesAnyGroup([]string{"other"}), "disjoint groups do not match")
	assert.True(t, settings.matchesAnyGroup([]string{"other", "g2"}), "any overlap matches")
}

func TestSignToken(t *testing.T) {
	settings := FlowSettings{TokenSecret: "testsecret"}

	payload, signature := settings.signToken("peer-1")

	require.NotEmpty(t, payload)
	require.NotEmpty(t, signature)

	mac := hmac.New(sha256.New, []byte("testsecret"))
	mac.Write([]byte(payload))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), signature,
		"signature must be the base64url HMAC-SHA256 over the payload")

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err, "payload must be base64url encoded")
	var claims tokenClaims
	require.NoError(t, json.Unmarshal(raw, &claims))
	assert.Equal(t, "peer-1", claims.PeerID)
	assert.Equal(t, int64(flowTokenLifetime.Seconds()), claims.ExpiresAt-claims.IssuedAt,
		"token lifetime must match the configured constant")
}
