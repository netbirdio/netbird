package certproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLegacyKeyError_NamesTheKeySpecAndTheRemedy(t *testing.T) {
	for spec, want := range map[uint32]string{atKeyExchange: "AT_KEYEXCHANGE", atSignature: "AT_SIGNATURE", 7: "key spec 7"} {
		err := legacyKeyError(spec)
		assert.ErrorIs(t, err, errLegacyKey, "callers can tell a legacy key from other failures")
		assert.ErrorContains(t, err, want, "the key spec found is named")
		assert.ErrorContains(t, err, "key storage provider", "the error says how to fix the enrolment")
	}
}
