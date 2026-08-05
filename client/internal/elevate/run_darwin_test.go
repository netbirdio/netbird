package elevate

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// The framework has to load and the symbols has to resolve, or nothing else here
// means anything.
func TestSecurityFrameworkLoads(t *testing.T) {
	if err := load(); err != nil {
		t.Fatalf("load() = %v, want the framework to open", err)
	}
	for name, fn := range map[string]any{
		"AuthorizationCreate":                authorizationCreate,
		"AuthorizationExecuteWithPrivileges": authorizationExecuteWithPrivileges,
		"AuthorizationFree":                  authorizationFree,
		"fileno":                             fileno,
		"fclose":                             fclose,
	} {
		if fn == nil {
			t.Errorf("%s did not resolve", name)
		}
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

	if got := rights.count; got != 1 {
		t.Fatalf("rights.count = %d, want 1: the struct layout is wrong", got)
	}

	var authorization uintptr
	status := authorizationCreate(rights, environment, flagDefaults|flagExtendRights, &authorization)

	switch status {
	case errAuthorizationSuccess:
		// Credentials were already cached for this session.
		authorizationFree(authorization, flagDestroyRights)
	case errAuthorizationDenied, errAuthorizationInteractionNotAllowed:
		// The expected answers when nobody may be asked.
	default:
		t.Fatalf("AuthorizationCreate returned OSStatus %d, want a known one", status)
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
		t.Fatal("a right that does not exist was granted")
	}
}

func TestMechanismAvailable(t *testing.T) {
	if !mechanismAvailable() {
		t.Error("mechanismAvailable() = false on macOS, where the trampoline always exists")
	}
}

// The one-shot's report is what stands in for an exit status here, so a run that
// says nothing must not read as success.
func TestExecuteRequiresTheAppliedMarker(t *testing.T) {
	if !strings.Contains(AppliedMarker, "netbird") {
		t.Errorf("AppliedMarker = %q, want something the one-shot would not print by accident", AppliedMarker)
	}
}

// A panic out of the FFI layer has to reach the caller as "no mechanism", which is
// the outcome that offers the user the command instead of taking the window down.
func TestGuardTurnsAPanicIntoUnavailable(t *testing.T) {
	err := guard("pretending to call something", func() error {
		panic("purego: signature it cannot map")
	})

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("guard() = %v, want it to be ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "pretending to call something") {
		t.Errorf("guard() = %v, want it to name what panicked", err)
	}
}

func TestGuardPassesErrorsThrough(t *testing.T) {
	sentinel := errors.New("the call itself failed")
	if err := guard("calling", func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("guard() = %v, want the error it was given", err)
	}
	if err := guard("calling", func() error { return nil }); err != nil {
		t.Errorf("guard() = %v, want nil", err)
	}
}

func TestFirstLine(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "", want: "no output"},
		{in: "  \n ", want: "no output"},
		{in: "one line", want: "one line"},
		{in: "first\nsecond", want: "first"},
	}
	for _, tt := range tests {
		if got := firstLine(tt.in); got != tt.want {
			t.Errorf("firstLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Declined has to stay distinguishable after wrapping, which is what the callers
// switch on.
func TestErrDeclinedSurvivesWrapping(t *testing.T) {
	if !errors.Is(errors.Join(ErrDeclined), ErrDeclined) {
		t.Error("ErrDeclined does not match itself through errors.Is")
	}
}
