package k8s

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLeaseNameForDomain(t *testing.T) {
	tests := []struct {
		domain string
	}{
		{"example.com"},
		{"app.example.com"},
		{"another.domain.io"},
	}

	seen := make(map[string]string)
	for _, tc := range tests {
		name := LeaseNameForDomain(tc.domain)

		assert.True(t, len(name) <= 63, "must be valid DNS label length")
		assert.Regexp(t, `^cert-lock-[0-9a-f]{16}$`, name,
			"must match expected format for domain %q", tc.domain)

		// Same input produces same output.
		assert.Equal(t, name, LeaseNameForDomain(tc.domain), "must be deterministic")

		// Different domains produce different names.
		if prev, ok := seen[name]; ok {
			t.Errorf("collision: %q and %q both map to %s", prev, tc.domain, name)
		}
		seen[name] = tc.domain
	}
}

func TestMicroTimeJSON(t *testing.T) {
	ts := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	mt := &MicroTime{Time: ts}

	data, err := json.Marshal(mt)
	require.NoError(t, err)
	assert.Equal(t, `"2024-06-15T10:30:00.000000Z"`, string(data))

	var decoded MicroTime
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.True(t, ts.Equal(decoded.Time), "round-trip should preserve time")
}

func TestMicroTimeNullJSON(t *testing.T) {
	// Null pointer serializes as JSON null via the Lease struct.
	spec := LeaseSpec{
		HolderIdentity: nil,
		AcquireTime:    nil,
		RenewTime:      nil,
	}

	data, err := json.Marshal(spec)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"acquireTime":null`)
	assert.Contains(t, string(data), `"renewTime":null`)
}

func TestLeaseJSONRoundTrip(t *testing.T) {
	holder := "pod-abc"
	dur := int32(300)
	now := MicroTime{Time: time.Now().UTC().Truncate(time.Microsecond)}

	original := Lease{
		APIVersion: "coordination.k8s.io/v1",
		Kind:       "Lease",
		Metadata: LeaseMetadata{
			Name:            "cert-lock-abcdef0123456789",
			Namespace:       "default",
			ResourceVersion: "12345",
			Annotations: map[string]string{
				"netbird.io/domain": "app.example.com",
			},
		},
		Spec: LeaseSpec{
			HolderIdentity:       &holder,
			LeaseDurationSeconds: &dur,
			AcquireTime:          &now,
			RenewTime:            &now,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Lease
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Metadata.Name, decoded.Metadata.Name)
	assert.Equal(t, original.Metadata.ResourceVersion, decoded.Metadata.ResourceVersion)
	assert.Equal(t, *original.Spec.HolderIdentity, *decoded.Spec.HolderIdentity)
	assert.Equal(t, *original.Spec.LeaseDurationSeconds, *decoded.Spec.LeaseDurationSeconds)
	assert.True(t, original.Spec.AcquireTime.Equal(decoded.Spec.AcquireTime.Time))
}
