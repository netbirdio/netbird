package ipcauth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

// Every method names what it does, so a refusal can say what was refused rather
// than quoting a level at the user.
func TestPoliciesDeclareAnAction(t *testing.T) {
	for method, policy := range methodPolicies {
		assert.NotEmpty(t, policy.Action, "%s declares no Action, its refusals cannot name the operation", method)
	}
}

// A refusal that names no action cannot say what was refused, and a privileged
// method drops to a bare message without one.
func TestPrivilegedPoliciesDeclareAnAction(t *testing.T) {
	for method, policy := range methodPolicies {
		if policy.Level != AuthzLevelPrivileged {
			continue
		}
		assert.NotEmpty(t, policy.Action, "%s requires privilege but declares no Action", method)
	}
}

// ownedByAnother is the profile most of these refusals are about: it exists and
// records an owner, that owner is simply not this caller.
var ownedByAnother = Target{Path: "/profiles/someone-else.json"}

// unownedProfile records no owner, which is what a machine set up with nobody at
// its console leaves behind.
var unownedProfile = Target{Path: "/profiles/default.json", UnOwned: true, Handle: "default"}

func TestDenyPolicyLevelCarriesPrivilegeGuidance(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "ClaimProfile",
	}

	err := denyPolicyLevel(req, methodPolicies[servicePath+"ClaimProfile"], unownedProfile)
	require.Error(t, err)

	st := gstatus.Convert(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if got, ok := d.(*errdetails.ErrorInfo); ok {
			info = got
		}
	}
	require.NotNil(t, info, "a privilege refusal must be machine readable")
	assert.Equal(t, ErrorReasonPrivilegeRequired, info.GetReason())
	assert.Equal(t, ErrorDomain, info.GetDomain())
	assert.NotEmpty(t, info.GetMetadata()[ErrorMetaSummary])
	assert.Contains(t, info.GetMetadata()[ErrorMetaCommand], "netbird profile claim default",
		"the guidance names the profile the request resolved to, not a placeholder")
}

// A profile that belongs to somebody else is explained, not answered with sudo.
func TestDenyPolicyLevelExplainsAProfileOwnedByAnother(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "SetConfig",
		State:    stubState{},
	}

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"SetConfig"], ownedByAnother))
	assert.Equal(t, ErrorReasonNotProfileOwner, info.GetReason())
	assert.Contains(t, info.GetMetadata()[ErrorMetaSummary], "belongs to another user")

	_, hasCommand := info.GetMetadata()[ErrorMetaCommand]
	assert.False(t, hasCommand, "privilege is not what the method asked for")
}

// A privileged method that declares nothing still refuses, it just cannot say
// how to satisfy it. This is the methodPolicyFor fallback for an unknown RPC.
func TestDenyPolicyLevelWithoutGuidanceStaysBare(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "NotARealMethod",
	}

	err := denyPolicyLevel(req, methodPolicyFor(req.Method), ownedByAnother)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, gstatus.Convert(err).Code())
	assert.Empty(t, gstatus.Convert(err).Details())
}

// stubState stands in for the daemon so a denial can be built without a server.
type stubState struct {
	holder    Principal
	running   bool
	target    Target
	targetErr error
}

func (s stubState) SessionHolder() (Principal, bool) { return s.holder, s.running }

func (s stubState) ResolveTarget(Identity, string) (Target, error) { return s.target, s.targetErr }

// A refusal caused by somebody else's connection explains itself and offers no
// command, since the caller cannot end a session that is not theirs.
//
// Profile owner is the whole input: denyPolicyLevel reads the level and nothing
// else, and resolveLevel only ever hands it that level when a session is
// running and somebody else holds it. TestAuthorizeBlamesAHeldSession is what
// holds those two together.
func TestDenyPolicyLevelExplainsAHeldSession(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelProfileOwner,
		Method:   servicePath + "Up",
	}

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"Up"], ownedByAnother))
	assert.Equal(t, ErrorReasonSessionHeld, info.GetReason())

	summary := info.GetMetadata()[ErrorMetaSummary]
	assert.Contains(t, summary, "Connecting", "the summary names what was refused")
	assert.Contains(t, summary, "another user")
	assert.NotContains(t, summary, "4242", "who holds it is not the caller's business")

	// An administrator outranks the session holder, so taking the connection
	// down is a remedy the caller can actually be pointed at.
	assert.Contains(t, info.GetMetadata()[ErrorMetaCommand], "netbird down")
}

// A caller who never owned the profile is refused for the profile, whatever the
// connection is doing.
func TestDenyPolicyLevelBelowProfileOwnerBlamesOwnership(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "Up",
	}

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"Up"], ownedByAnother))
	assert.Equal(t, ErrorReasonNotProfileOwner, info.GetReason())
	assert.Contains(t, info.GetMetadata()[ErrorMetaSummary], "belongs to another user")
	assert.NotContains(t, info.GetMetadata()[ErrorMetaSummary], "connected",
		"the refusal is about the profile, so it must not blame a connection")

	_, hasCommand := info.GetMetadata()[ErrorMetaCommand]
	assert.False(t, hasCommand, "ending a session does not make the profile theirs")
}

// A method with no Action still refuses, it just cannot name the operation.
func TestSessionHeldSummaryWithoutAnAction(t *testing.T) {
	assert.Contains(t, sessionHeldSummary(""), "This command is refused")
	assert.Contains(t, sessionHeldSummary("connecting"), "Connecting is refused")
}

// denialDetail pulls the machine readable half out of a refusal.
func denialDetail(t *testing.T, err error) *errdetails.ErrorInfo {
	t.Helper()
	require.Error(t, err)

	st := gstatus.Convert(err)
	require.Equal(t, codes.PermissionDenied, st.Code())

	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			require.Equal(t, ErrorDomain, info.GetDomain())
			return info
		}
	}
	t.Fatal("refusal carries no ErrorInfo detail")
	return nil
}

// DenialFrom is the one reader of the detail the builders attach, so the CLI and
// the UI cannot drift on what counts as a refusal.
func TestDenialFromReadsEveryReason(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		reason  string
		command bool
	}{
		{"privilege", PrivilegeError("Claiming a profile requires root.", "sudo netbird profile claim"), ErrorReasonPrivilegeRequired, true},
		{"session held", SessionHeldError("connecting"), ErrorReasonSessionHeld, true},
		{"not owner", NotOwnerError("switching profile"), ErrorReasonNotProfileOwner, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denial, ok := DenialFrom(tc.err)
			require.True(t, ok)
			assert.Equal(t, tc.reason, denial.Reason)
			assert.NotEmpty(t, denial.Summary)
			assert.Equal(t, tc.command, denial.Command != "")
		})
	}
}

func TestDenialFromIgnoresWhatIsNotOurs(t *testing.T) {
	_, ok := DenialFrom(nil)
	assert.False(t, ok)

	_, ok = DenialFrom(errors.New("connection refused"))
	assert.False(t, ok, "a plain error explains no refusal")

	_, ok = DenialFrom(gstatus.Error(codes.PermissionDenied, "denied"))
	assert.False(t, ok, "a status with no detail of ours is not ours to reword")
}

// A wrap must not hide the refusal, since commands add context before printing.
func TestDenialFromSeesThroughWrapping(t *testing.T) {
	denial, ok := DenialFrom(fmt.Errorf("up failed: %w", SessionHeldError("connecting")))
	require.True(t, ok)
	assert.Equal(t, ErrorReasonSessionHeld, denial.Reason)
}

// A detail with no summary still refused something, so the status message stands
// in rather than leaving a consumer with nothing to show.
func TestDenialFromFallsBackToTheStatusMessage(t *testing.T) {
	st, err := gstatus.New(codes.PermissionDenied, "refused for reasons").WithDetails(&errdetails.ErrorInfo{
		Reason: ErrorReasonSessionHeld,
		Domain: ErrorDomain,
	})
	require.NoError(t, err)

	denial, ok := DenialFrom(st.Err())
	require.True(t, ok)
	assert.Equal(t, "refused for reasons", denial.Summary)
}

// A profile nobody has claimed is the headless install: the caller is not being
// kept out of somebody else's profile, they are being told to record an owner.
func TestDenyPolicyLevelOffersTheClaimForAnUnownedProfile(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "Up",
	}

	stubConsoleLookup(t, false)

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"Up"], unownedProfile))
	assert.Equal(t, ErrorReasonProfileUnowned, info.GetReason())

	summary := info.GetMetadata()[ErrorMetaSummary]
	assert.Contains(t, summary, "Connecting", "the summary names what was refused")
	assert.Contains(t, summary, "no owner on record")
	assert.NotContains(t, summary, "another user",
		"nobody owns it, so blaming another user would be untrue")

	// Without the sudo prefix, which RequiredActor drops for a daemon that is
	// not itself privileged, as this test process is not.
	assert.Contains(t, info.GetMetadata()[ErrorMetaCommand], "netbird profile claim default",
		"the command names the profile that was refused")
}

// The same refusal reaches a method that only needs profile owner, so a settings
// read on a fresh headless machine explains itself the same way connecting does.
func TestDenyPolicyLevelOffersTheClaimBelowSessionHolderToo(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "GetConfig",
	}

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"GetConfig"], unownedProfile))
	assert.Equal(t, ErrorReasonProfileUnowned, info.GetReason())
	assert.Contains(t, info.GetMetadata()[ErrorMetaCommand], "netbird profile claim default")
}

// A session somebody else holds outranks the profile having no owner: the
// connection is what is in the way, and ending it is the remedy.
func TestDenyPolicyLevelKeepsTheHeldSessionAheadOfOwnership(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelProfileOwner,
		Method:   servicePath + "Up",
	}

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"Up"], unownedProfile))
	assert.Equal(t, ErrorReasonSessionHeld, info.GetReason())
}

// The claim command names the profile it is going to act on.
func TestClaimCommandNamesTheProfile(t *testing.T) {
	assert.Equal(t, ElevatedCommand("netbird profile claim default"), ClaimCommand("default"))
	assert.Equal(t, ElevatedCommand("netbird profile claim <profile>"), ClaimCommand(""),
		"with no profile to name the caller fills in the placeholder")
}

// stubConsoleLookup decides whether a caller counts as being at the console,
// without the machine running the test having a seat of its own.
func stubConsoleLookup(t *testing.T, atConsole bool) {
	t.Helper()
	orig := consoleLookup
	consoleLookup = func(Identity) bool { return atConsole }
	t.Cleanup(func() { consoleLookup = orig })
}

// A caller away from the console is told what normally claims a profile, since
// a machine set up without one is how it goes unclaimed.
func TestUnownedSummaryNamesTheConsoleAwayFromIt(t *testing.T) {
	summary := unownedSummary("connecting", false)

	assert.Contains(t, summary, "has no owner on record")
	assert.Contains(t, summary, "console")
	assert.Contains(t, summary, "An explicit claim of the profile is needed.")
}

// A caller at the console who still finds no owner got here another way, a
// migration that did not finish among them.
func TestUnownedSummaryStaysQuietAboutTheConsoleAtIt(t *testing.T) {
	summary := unownedSummary("connecting", true)

	assert.Contains(t, summary, "has no owner on record")
	assert.NotContains(t, summary, "console")
	assert.Contains(t, summary, "An explicit claim of the profile is needed.",
		"the remedy is the same wherever the caller is sitting")
}

// The reason and the command do not move with the caller, only the explanation
// of how the profile came to be unowned does.
func TestDenyOwnershipKeepsTheClaimForAConsoleCaller(t *testing.T) {
	stubConsoleLookup(t, true)

	info := denialDetail(t, denyOwnership("connecting", KnownForTest(Identity{UID: 1000}), unownedProfile))
	assert.Equal(t, ErrorReasonProfileUnowned, info.GetReason())
	assert.Contains(t, info.GetMetadata()[ErrorMetaCommand], "netbird profile claim default")
	assert.NotContains(t, info.GetMetadata()[ErrorMetaSummary], "console")
}

// Two commands put an authorization refusal right, ending the session and
// recording an owner. Whatever a denial hands the caller is one of them.
func TestDenialsOfferOnlyTheTwoRemedies(t *testing.T) {
	_, down := RequiredActor(DownCommand())
	_, claim := RequiredActor(ClaimCommand(unownedProfile.Handle))

	for name, err := range map[string]error{
		"privileged":   denyPrivileged(methodPolicies[servicePath+"ClaimProfile"], unownedProfile),
		"session held": SessionHeldError("connecting"),
		"unowned":      UnownedError("connecting", unownedProfile.Handle, false),
		"not owner":    NotOwnerError("connecting"),
	} {
		t.Run(name, func(t *testing.T) {
			denial, ok := DenialFrom(err)
			require.True(t, ok, "every refusal has to be machine readable")
			if denial.Command == "" {
				return
			}
			assert.Contains(t, []string{down, claim}, denial.Command,
				"a refusal offered a command that is neither remedy")
		})
	}
}

// A sudo prefix already says who has to run the command, so repeating it in the
// summary would be noise.
func TestRemedyNoteStaysQuietBehindSudo(t *testing.T) {
	assert.Empty(t, remedyNote("root", "sudo netbird down"))
}

// Windows has no sudo to prefix and neither does a delegating daemon, so the
// summary is the only place that can name who must run the command.
func TestRemedyNoteNamesTheActorWithoutSudo(t *testing.T) {
	assert.Equal(t, " Running this requires administrator privileges.",
		remedyNote("administrator privileges", "netbird down"))
}

// The refusal a user hits when somebody else holds the session has to say what
// running the command it offers takes.
func TestSessionHeldSaysWhatRunningTheCommandTakes(t *testing.T) {
	denial, ok := DenialFrom(SessionHeldError("switching profile"))
	require.True(t, ok)

	actor, command := RequiredActor(DownCommand())
	require.NotContains(t, command, "sudo ", "this test process runs a delegating daemon")
	assert.Contains(t, denial.Summary, "Running this requires "+actor)
}
