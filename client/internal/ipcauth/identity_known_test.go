package ipcauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The zero Identity carries uid 0, so every predicate that reads UID has to
// refuse it explicitly without the known marker.
func TestZeroIdentityIsInert(t *testing.T) {
	var zero Identity

	assert.False(t, zero.Known(), "the zero identity must not be known")
	assert.False(t, zero.IsPrivileged(), "the zero identity must not read as root")
	assert.False(t, zero.SameUser(Identity{}), "two unknown identities must not match")
	assert.False(t, zero.SameUser(Identity{known: true, UID: 0}), "an unknown identity must not match root")
	assert.False(t, Identity{known: true, UID: 0}.SameUser(zero), "SameUser must be symmetric here too")
	assert.Equal(t, "unidentified", zero.String(), "an unknown identity must not print as uid=0")
}

// IsDaemonSelf compares UIDs, so on the usual install, where the daemon is root,
// an unknown identity would match it.
func TestIsDaemonSelfRejectsUnknownIdentity(t *testing.T) {
	prevID, prevDelegate := selfIdentity, selfMayDelegate
	t.Cleanup(func() { selfIdentity, selfMayDelegate = prevID, prevDelegate })

	selfIdentity = Identity{known: true, UID: 0}
	selfMayDelegate = false

	assert.False(t, IsDaemonSelf(Identity{}), "an unknown identity is not the daemon")
	assert.True(t, IsDaemonSelf(Identity{known: true, UID: 0}), "precondition: a known root caller is the daemon here")
}

// A daemon whose own identity could not be read delegates to nobody, and the
// zero selfIdentity is what records that.
func TestUnknownSelfDelegatesToNobody(t *testing.T) {
	prevID, prevDelegate := selfIdentity, selfMayDelegate
	t.Cleanup(func() { selfIdentity, selfMayDelegate = prevID, prevDelegate })

	selfIdentity = Identity{}
	selfMayDelegate = true

	assert.False(t, IsDaemonSelf(Identity{known: true, UID: 1000}))
	_, delegates := SelfDelegatesTo()
	assert.False(t, delegates, "an unknown self identity must not be delegated to")
}

func TestKnownForTestMarksIdentity(t *testing.T) {
	id := KnownForTest(Identity{UID: 1000, GID: 1000})
	require.True(t, id.Known())
	assert.Equal(t, uint32(1000), id.UID, "KnownForTest must not alter the identity")
}

// A uid:0 owner is a config value, so it grants nothing on its own.
func TestConfigOwnerCannotGrantPrivilege(t *testing.T) {
	root, ok := ParsePrincipal("uid:0")
	require.True(t, ok)
	assert.False(t, root.Matches(KnownForTest(Identity{UID: 1000})),
		"a root owner must not match an unrelated caller")
}

// Group ownership is not supported yet, so a group SID in an owner field must
// not match a caller who merely belongs to that group.
func TestPrincipalDoesNotMatchGroupSID(t *testing.T) {
	group, ok := ParsePrincipal("sid:S-1-5-21-1-2-3-513")
	require.True(t, ok)

	member := KnownForTest(Identity{
		SID:    "S-1-5-21-1-2-3-1001",
		Groups: []string{"S-1-5-21-1-2-3-513"},
	})
	assert.False(t, group.Matches(member), "a group SID owner must not match a group member")
}

func TestPrincipalMatchingIsPlatformScoped(t *testing.T) {
	unix, ok := ParsePrincipal("uid:1000")
	require.True(t, ok)
	windows, ok := ParsePrincipal("sid:S-1-5-21-1-2-3-1001")
	require.True(t, ok)

	unixCaller := KnownForTest(Identity{UID: 1000})
	windowsCaller := KnownForTest(Identity{SID: "S-1-5-21-1-2-3-1001"})

	assert.True(t, unix.Matches(unixCaller))
	assert.True(t, windows.Matches(windowsCaller))
	assert.False(t, unix.Matches(windowsCaller), "uid must never match a windows identity")
	assert.False(t, windows.Matches(unixCaller), "sid must never match a unix identity")
}

func TestPrincipalDoesNotMatchUnknownIdentity(t *testing.T) {
	p, ok := ParsePrincipal("uid:0")
	require.True(t, ok)
	assert.False(t, p.Matches(Identity{}), "an unknown caller matches no principal")
}
