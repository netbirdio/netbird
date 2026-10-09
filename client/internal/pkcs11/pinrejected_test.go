package pkcs11

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPINRejected(t *testing.T) {
	for _, code := range []uint{rvPINIncorrect, rvPINInvalid, rvPINLenRange, rvPINExpired, rvPINLocked} {
		err := fmt.Errorf("open session: %w", Error{Op: "C_Login", Code: code})
		assert.True(t, PINRejected(err), "CKR 0x%x refuses the PIN, also when wrapped", code)
	}
	assert.False(t, PINRejected(Error{Op: "C_Login", Code: 0x30}), "a device error says nothing about the PIN")
	assert.False(t, PINRejected(errors.New("CKR_PIN_INCORRECT")), "only a PKCS#11 return value counts")
	assert.False(t, PINRejected(nil))
}
