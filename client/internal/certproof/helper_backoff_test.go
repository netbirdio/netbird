package certproof

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// TestHelperBackoff: a user whose helper proved nothing, for one ignoring or denying a
// keychain prompt, is not asked again for the same CAs within the quiet period, while a
// success or other CAs are asked at once.
func TestHelperBackoff(t *testing.T) {
	now := time.Now()
	b := newHelperBackoff()
	key := helperBackoffKey("501", []*proto.CertificateChallenge{{CaCertificates: []string{"ca-a"}}})

	assert.True(t, b.allow(key, now), "a user never asked is asked")

	b.record(key, false, now)
	assert.False(t, b.allow(key, now.Add(helperQuietPeriod-time.Second)), "no new prompt within the quiet period")
	assert.True(t, b.allow(key, now.Add(helperQuietPeriod)), "asked again once the quiet period passed")

	other := helperBackoffKey("501", []*proto.CertificateChallenge{{CaCertificates: []string{"ca-b"}}})
	assert.True(t, b.allow(other, now), "a check for other CAs is asked at once")
	assert.True(t, b.allow(helperBackoffKey("502", []*proto.CertificateChallenge{{CaCertificates: []string{"ca-a"}}}), now), "another user is asked at once")

	b.record(key, true, now)
	assert.True(t, b.allow(key, now), "a run that proved something clears the quiet period")
}

// TestHelperBackoffKey_IgnoresNonces: nonces rotate every window without changing what
// the user is asked to prove, so they do not reset the quiet period.
func TestHelperBackoffKey_IgnoresNonces(t *testing.T) {
	a := helperBackoffKey("501", []*proto.CertificateChallenge{{Nonce: []byte("one"), CaCertificates: []string{"ca"}}})
	b := helperBackoffKey("501", []*proto.CertificateChallenge{{Nonce: []byte("two"), CaCertificates: []string{"ca"}}})
	assert.Equal(t, a, b, "the key does not depend on the nonce")
}

// TestHelperBackoffKey_IgnoresOrder: the same CAs, listed in another order or with the
// challenges reordered, are the same question to the user.
func TestHelperBackoffKey_IgnoresOrder(t *testing.T) {
	a := helperBackoffKey("501", []*proto.CertificateChallenge{
		{CaCertificates: []string{"ca-1", "ca-2"}},
		{CaCertificates: []string{"ca-3"}},
	})
	b := helperBackoffKey("501", []*proto.CertificateChallenge{
		{CaCertificates: []string{"ca-3"}},
		{CaCertificates: []string{"ca-2", "ca-1"}},
	})
	assert.Equal(t, a, b, "the key does not depend on the order of CAs or challenges")

	c := helperBackoffKey("501", []*proto.CertificateChallenge{{CaCertificates: []string{"ca-1", "ca-2", "ca-3"}}})
	assert.NotEqual(t, a, c, "the same CAs grouped into other challenges are another question")
}

// TestHelperBackoff_PrunesExpired: entries whose quiet period passed are dropped when the
// next outcome is recorded, so the map does not grow with every user and CA set seen.
func TestHelperBackoff_PrunesExpired(t *testing.T) {
	now := time.Now()
	b := newHelperBackoff()
	b.record("old", false, now)
	b.record("new", false, now.Add(helperQuietPeriod))

	assert.NotContains(t, b.until, "old", "an expired entry is pruned")
	assert.Contains(t, b.until, "new", "a current entry is kept")
}
