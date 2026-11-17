package elevate

import (
	"errors"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The framework has to load and the symbols have to resolve, or nothing else here
// means anything.
func TestSecurityFrameworkLoads(t *testing.T) {
	require.NoError(t, load(), "Security.framework must open")

	for name, fn := range map[string]any{
		"AuthorizationCreate":                authorizationCreate,
		"AuthorizationExecuteWithPrivileges": authorizationExecuteWithPrivileges,
		"AuthorizationFree":                  authorizationFree,
		"fileno":                             fileno,
		"fclose":                             fclose,
	} {
		assert.NotNil(t, fn, "%s must resolve", name)
	}
}

// A request with no interaction allowed exercises the whole call — the rights and
// environment structs, and the OSStatus that comes back — without a dialog anybody
// has to answer. What the system decides is its business; that it decides at all is
// what this asserts.
func TestAuthorizationCreateWithoutInteraction(t *testing.T) {
	if err := load(); err != nil {
		t.Skipf("Security.framework did not open: %v", err)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	rights := itemSet(&pinner, authorizationItem{name: cString(&pinner, rightExecute)})
	environment := itemSet(&pinner, promptItem(&pinner))
	require.EqualValues(t, 1, rights.count, "the rights struct layout must match the C one")

	var authorization uintptr
	status := authorizationCreate(rights, environment, flagDefaults|flagExtendRights, &authorization)

	switch status {
	case errAuthorizationSuccess:
		// Credentials were already cached for this session.
		authorizationFree(authorization, flagDestroyRights)
	case errAuthorizationDenied, errAuthorizationInteractionNotAllowed:
		// The expected answers when nobody may be asked.
	default:
		require.Failf(t, "unknown OSStatus", "AuthorizationCreate returned %d, want a status we recognise", status)
	}
}

// Asking with a right nobody has must not be mistaken for a declined prompt: the
// caller would report nothing at all.
func TestAuthorizeUnknownRightIsNotDeclined(t *testing.T) {
	if err := load(); err != nil {
		t.Skipf("Security.framework did not open: %v", err)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	rights := itemSet(&pinner, authorizationItem{name: cString(&pinner, "io.netbird.right.that.does.not.exist")})

	var authorization uintptr
	status := authorizationCreate(rights, nil, flagDefaults|flagExtendRights, &authorization)
	if status == errAuthorizationSuccess {
		authorizationFree(authorization, flagDestroyRights)
	}
	assert.NotEqual(t, int32(errAuthorizationSuccess), status, "a right that does not exist must not be granted")
}

func TestMechanismAvailable(t *testing.T) {
	assert.True(t, mechanismAvailable(), "the trampoline exists on every macOS")
}

// The one-shot's report is what stands in for an exit status here, so a run that
// says nothing must not read as success.
func TestCheckApplied(t *testing.T) {
	require.NoError(t, checkApplied(AppliedMarker+"\n"), "the report the one-shot prints")
	require.NoError(t, checkApplied("some warning\n"+AppliedMarker+"\n"), "the report after other output")

	assert.Error(t, checkApplied(""), "a run that printed nothing did not apply the change")
	assert.Error(t, checkApplied("dyld: library not loaded\n"), "output that is not the report")
}

// A panic out of the FFI layer has to reach the caller as "no mechanism", which is
// the outcome that offers the user the command instead of taking the window down.
func TestGuardTurnsAPanicIntoUnavailable(t *testing.T) {
	err := guard("pretending to call something", func() error {
		panic("purego: signature it cannot map")
	})

	require.ErrorIs(t, err, ErrUnavailable, "a panic must read as a missing mechanism")
	assert.Contains(t, err.Error(), "pretending to call something", "what panicked")
}

// guard wraps every darwin path, so what a caller switches on has to survive it.
func TestGuardPassesErrorsThrough(t *testing.T) {
	sentinel := errors.New("the call itself failed")
	assert.ErrorIs(t, guard("calling", func() error { return sentinel }), sentinel,
		"the error it was given")
	assert.ErrorIs(t, guard("calling", func() error { return ErrDeclined }), ErrDeclined,
		"a declined prompt stays declined")
	assert.NoError(t, guard("calling", func() error { return nil }), "a call that worked")
}
