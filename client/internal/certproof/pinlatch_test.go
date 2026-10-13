package certproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRejectedPINKey_ScopesToModuleTokenAndPIN(t *testing.T) {
	base := rejectedPINKey("/lib/a.so", "netbird", []byte("1234"))

	assert.Equal(t, base, rejectedPINKey("/lib/a.so", "netbird", []byte("1234")), "the same PIN on the same token is the same key")
	assert.NotEqual(t, base, rejectedPINKey("/lib/a.so", "netbird", []byte("4321")), "a corrected PIN must be tried")
	assert.NotEqual(t, base, rejectedPINKey("/lib/a.so", "piv", []byte("1234")), "a PIN rejected by one token is still tried on another")
	assert.NotEqual(t, base, rejectedPINKey("/lib/b.so", "netbird", []byte("1234")), "a PIN rejected through one module is still tried through another")
	assert.NotEqual(t, rejectedPINKey("ab", "", []byte("1")), rejectedPINKey("a", "b", []byte("1")),
		"field boundaries are part of the key, so shifted fields do not collide")
}

func TestPINLatch_RemembersRejectedKeys(t *testing.T) {
	latch := &pinLatch{keys: map[[32]byte]struct{}{}}
	rejected := rejectedPINKey("/lib/a.so", "netbird", []byte("0000"))
	other := rejectedPINKey("/lib/a.so", "netbird", []byte("1234"))

	assert.False(t, latch.has(rejected), "nothing is rejected before a login fails")
	latch.add(rejected)
	assert.True(t, latch.has(rejected), "a rejected PIN is not tried again")
	assert.False(t, latch.has(other), "other PINs are unaffected")
}
