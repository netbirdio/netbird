package pkcs11

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDriver stands in for a loaded module and records the calls a session makes.
type fakeDriver struct {
	loginErr error
	logouts  int
	closes   int
}

func (f *fakeDriver) tokens() ([]Token, error)             { return []Token{{Slot: 1, Label: "netbird"}}, nil }
func (f *fakeDriver) openSession(uint, bool) (uint, error) { return 7, nil }
func (f *fakeDriver) closeSession(uint)                    { f.closes++ }
func (f *fakeDriver) login(uint, []byte) error             { return f.loginErr }
func (f *fakeDriver) logout(uint)                          { f.logouts++ }
func (f *fakeDriver) findObjects(uint, []Attribute) ([]Object, error) {
	return nil, nil
}
func (f *fakeDriver) attribute(uint, Object, uint) ([]byte, error) { return nil, nil }
func (f *fakeDriver) sign(uint, Mechanism, Object, []byte) ([]byte, error) {
	return nil, nil
}
func (f *fakeDriver) createObject(uint, []Attribute) (Object, error) { return 0, nil }

func TestOpenSession_LogsOutOnlyALoginItOwns(t *testing.T) {
	t.Run("own login is logged out on close", func(t *testing.T) {
		d := &fakeDriver{}
		s, err := (&Module{d: d}).OpenSession("netbird", []byte("1234"))
		require.NoError(t, err)
		s.Close()
		assert.Equal(t, 1, d.logouts, "the session that logged in logs out again")
	})

	t.Run("login held by another session is left alone", func(t *testing.T) {
		d := &fakeDriver{loginErr: Error{Op: "C_Login", Code: rvUserAlreadyLoggedIn}}
		s, err := (&Module{d: d}).OpenSession("netbird", []byte("1234"))
		require.NoError(t, err, "an existing login is good enough to use the token")
		s.Close()
		assert.Zero(t, d.logouts, "logging out would end the login of the session that owns it")
		assert.Equal(t, 1, d.closes, "the session itself is still closed")
	})

	t.Run("rejected pin closes the session", func(t *testing.T) {
		d := &fakeDriver{loginErr: Error{Op: "C_Login", Code: rvPINIncorrect}}
		_, err := (&Module{d: d}).OpenSession("netbird", []byte("0000"))
		assert.True(t, PINRejected(err), "the PIN error reaches the caller")
		assert.Zero(t, d.logouts, "nothing to log out after a failed login")
		assert.Equal(t, 1, d.closes, "the session opened for the login is closed")
	})
}
