package mdm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy_NilSafe(t *testing.T) {
	var p *Policy
	assert.True(t, p.IsEmpty())
	assert.False(t, p.HasKey(KeyManagementURL))
	assert.Empty(t, p.ManagedKeys())

	_, ok := p.GetString(KeyManagementURL)
	assert.False(t, ok)
	_, ok = p.GetBool(KeyDisableProfiles)
	assert.False(t, ok)
	_, ok = p.GetStringSlice(KeySplitTunnelApps)
	assert.False(t, ok)
}

func TestPolicy_Empty(t *testing.T) {
	p := NewPolicy(nil)
	require.NotNil(t, p)
	assert.True(t, p.IsEmpty())
	assert.False(t, p.HasKey(KeyManagementURL))
	assert.Empty(t, p.ManagedKeys())
}

func TestPolicy_HasKey(t *testing.T) {
	p := NewPolicy(map[string]any{
		KeyManagementURL:    "https://corp.example.com",
		KeyDisableProfiles:  true,
	})
	assert.False(t, p.IsEmpty())
	assert.True(t, p.HasKey(KeyManagementURL))
	assert.True(t, p.HasKey(KeyDisableProfiles))
	assert.False(t, p.HasKey(KeyPreSharedKey))
}

func TestPolicy_ManagedKeysSorted(t *testing.T) {
	p := NewPolicy(map[string]any{
		KeyDisableProfiles: true,
		KeyManagementURL:   "https://x",
		KeyAllowServerSSH:  false,
	})
	got := p.ManagedKeys()
	assert.Equal(t, []string{KeyAllowServerSSH, KeyDisableProfiles, KeyManagementURL}, got)
}

func TestPolicy_GetString(t *testing.T) {
	p := NewPolicy(map[string]any{
		KeyManagementURL:   "https://corp.example.com",
		KeyDisableProfiles: true,            // wrong type for GetString
		KeyPreSharedKey:        "",              // empty rejected
	})
	v, ok := p.GetString(KeyManagementURL)
	assert.True(t, ok)
	assert.Equal(t, "https://corp.example.com", v)

	_, ok = p.GetString(KeyDisableProfiles)
	assert.False(t, ok, "non-string value must not be reported as string")

	_, ok = p.GetString(KeyPreSharedKey)
	assert.False(t, ok, "empty string treated as unset")

	_, ok = p.GetString("nonexistent")
	assert.False(t, ok)
}

func TestPolicy_GetBool(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want bool
		ok   bool
	}{
		{"native true", true, true, true},
		{"native false", false, false, true},
		{"string true", "true", true, true},
		{"string false", "false", false, true},
		{"string 1", "1", true, true},
		{"string 0", "0", false, true},
		{"string yes", "yes", true, true},
		{"string no", "no", false, true},
		{"int nonzero", 1, true, true},
		{"int zero", 0, false, true},
		{"int64 nonzero", int64(2), true, true},
		{"int64 zero", int64(0), false, true},
		{"string garbage", "maybe", false, false},
		{"float unsupported", 1.0, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewPolicy(map[string]any{KeyDisableProfiles: c.raw})
			got, ok := p.GetBool(KeyDisableProfiles)
			assert.Equal(t, c.ok, ok)
			if c.ok {
				assert.Equal(t, c.want, got)
			}
		})
	}

	_, ok := NewPolicy(nil).GetBool(KeyDisableProfiles)
	assert.False(t, ok)
}

func TestPolicy_GetStringSlice(t *testing.T) {
	t.Run("native string slice", func(t *testing.T) {
		p := NewPolicy(map[string]any{
			KeySplitTunnelApps: []string{"com.a", "com.b"},
		})
		got, ok := p.GetStringSlice(KeySplitTunnelApps)
		assert.True(t, ok)
		assert.Equal(t, []string{"com.a", "com.b"}, got)
	})

	t.Run("any slice of strings", func(t *testing.T) {
		p := NewPolicy(map[string]any{
			KeySplitTunnelApps: []any{"com.a", "com.b"},
		})
		got, ok := p.GetStringSlice(KeySplitTunnelApps)
		assert.True(t, ok)
		assert.Equal(t, []string{"com.a", "com.b"}, got)
	})

	t.Run("single string lifts to one-element slice", func(t *testing.T) {
		p := NewPolicy(map[string]any{
			KeySplitTunnelApps: "com.a",
		})
		got, ok := p.GetStringSlice(KeySplitTunnelApps)
		assert.True(t, ok)
		assert.Equal(t, []string{"com.a"}, got)
	})

	t.Run("mixed any slice rejected", func(t *testing.T) {
		p := NewPolicy(map[string]any{
			KeySplitTunnelApps: []any{"com.a", 1},
		})
		_, ok := p.GetStringSlice(KeySplitTunnelApps)
		assert.False(t, ok)
	})

	t.Run("missing key", func(t *testing.T) {
		p := NewPolicy(nil)
		_, ok := p.GetStringSlice(KeySplitTunnelApps)
		assert.False(t, ok)
	})
}

func TestLoadPolicy_PlatformStubReturnsEmpty(t *testing.T) {
	// loadPlatformPolicy is a stub on every OS for Phase 1. LoadPolicy must
	// degrade gracefully and never return nil.
	p := LoadPolicy()
	require.NotNil(t, p)
	assert.True(t, p.IsEmpty())
	assert.Empty(t, p.ManagedKeys())
}
