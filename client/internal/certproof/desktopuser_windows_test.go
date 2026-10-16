package certproof

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestCurrentDesktopUser_FindsTheOwnersSession runs against a real machine as LocalSystem,
// with NB_TEST_DESKTOP_OWNER naming an account that is signed in. That account's session
// must be found, and only that account's.
func TestCurrentDesktopUser_FindsTheOwnersSession(t *testing.T) {
	owner := os.Getenv("NB_TEST_DESKTOP_OWNER")
	if owner == "" {
		t.Skip("set NB_TEST_DESKTOP_OWNER to a signed-in account and run as LocalSystem")
	}
	user, ok := CurrentDesktopUser(owner)
	require.True(t, ok, "the signed-in owner %s must have a session", owner)
	defer user.Close()
	t.Logf("owner %s resolved to session %d as %s", owner, user.Session, user.Name)
	assert.True(t, sameAccountName(user.Name, owner), "the session found belongs to %s, not %s", owner, user.Name)
	assert.NotZero(t, user.Session, "session 0 hosts services and never belongs to the owner")

	console, consoleOK := CurrentDesktopUser("")
	if consoleOK {
		defer console.Close()
		t.Logf("without an owner the console user counts: session %d as %s", console.Session, console.Name)
	} else {
		t.Log("without an owner nobody counts: no user at the console")
	}
}
