package certproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSameAccountName(t *testing.T) {
	tests := []struct {
		session, owner string
		want           bool
	}{
		{`CORP\alice`, `CORP\alice`, true},
		{`CORP\alice`, `corp\ALICE`, true},
		{`CORP\alice`, `alice`, true},
		{`CORP\alice`, `OTHER\alice`, false},
		{`CORP\alice`, `bob`, false},
		{`alice`, `alice`, true},
		{`CORP\alice`, `CORP\alic`, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, sameAccountName(tt.session, tt.owner), "session %q, owner %q", tt.session, tt.owner)
	}
}

// CurrentDesktopUser against the real session manager: an owner no session belongs to
// must never yield a session, whoever else is signed in.
func TestCurrentDesktopUser_UnknownOwnerHasNoSession(t *testing.T) {
	user, ok := CurrentDesktopUser(`NO-SUCH-DOMAIN\no-such-user-netbird`)
	if ok {
		user.Close()
	}
	assert.False(t, ok, "a profile owner without a session must not borrow another user's store")
}
