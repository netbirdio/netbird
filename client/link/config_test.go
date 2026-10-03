package link

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCommand wires the flags the same way the binary does, so the tests
// exercise the real flag and environment plumbing.
func newTestCommand() (*cobra.Command, *rawConfig) {
	cmd := &cobra.Command{Use: "nblink"}
	return cmd, BindFlags(cmd)
}

func TestFlagNameToEnvVar(t *testing.T) {
	assert.Equal(t, "NB_FORWARD", FlagNameToEnvVar("forward"))
	assert.Equal(t, "NB_ALLOW_PUBLIC_BIND", FlagNameToEnvVar("allow-public-bind"))
	assert.Equal(t, "NB_MANAGEMENT_URL", FlagNameToEnvVar("management-url"))
}

func TestSetFlagsFromEnvVars(t *testing.T) {
	cmd, raw := newTestCommand()
	t.Setenv("NB_FORWARD", "http://8080=https://a.internal,http://8081=https://b.internal")
	t.Setenv("NB_MANAGEMENT_URL", "https://mgmt.example:443")

	require.NoError(t, SetFlagsFromEnvVars(cmd))

	assert.Equal(t, []string{"http://8080=https://a.internal", "http://8081=https://b.internal"},
		raw.forwards, "NB_FORWARD should split on commas into repeated forwards")
	assert.Equal(t, "https://mgmt.example:443", raw.managementURL)
}

// A value given on the command line must win over the environment, otherwise a
// container's baked-in defaults could not be overridden at run time.
func TestFlagBeatsEnvVar(t *testing.T) {
	cmd, raw := newTestCommand()
	require.NoError(t, cmd.PersistentFlags().Set("log-level", "debug"))
	t.Setenv("NB_LOG_LEVEL", "error")

	require.NoError(t, SetFlagsFromEnvVars(cmd))

	assert.Equal(t, "debug", raw.logLevel, "an explicit flag should not be overwritten by the environment")
}

// A container must not start with a configuration other than the one it was
// given, so an unparseable value stops startup instead of leaving the default.
func TestSetFlagsFromEnvVarsRejectsInvalidValue(t *testing.T) {
	cmd, raw := newTestCommand()
	t.Setenv("NB_ALLOW_PUBLIC_BIND", "yes-please")

	err := SetFlagsFromEnvVars(cmd)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "NB_ALLOW_PUBLIC_BIND", "the error should name the variable at fault")
	assert.False(t, raw.allowPublicBind, "the default must not be silently kept in effect")
}

func TestResolveRequiresForward(t *testing.T) {
	_, raw := newTestCommand()

	_, err := raw.Resolve()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one --forward")
}

func TestResolveGatesPublicBind(t *testing.T) {
	_, raw := newTestCommand()
	raw.forwards = []string{"http://0.0.0.0:8080=https://grafana.internal"}

	_, err := raw.Resolve()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow-public-bind",
		"binding a public address should require the explicit opt-in")
}

func TestResolveAllowsPublicBindWhenOptedIn(t *testing.T) {
	_, raw := newTestCommand()
	raw.forwards = []string{"http://0.0.0.0:8080=https://grafana.internal"}
	raw.allowPublicBind = true

	cfg, err := raw.Resolve()

	require.NoError(t, err)
	require.Len(t, cfg.Forwards, 1)
	assert.Equal(t, "0.0.0.0:8080", cfg.Forwards[0].Listen)
}

func TestResolveRejectsDuplicateListener(t *testing.T) {
	_, raw := newTestCommand()
	raw.forwards = []string{
		"http://8080=https://a.internal",
		"http://127.0.0.1:8080=https://b.internal",
	}

	_, err := raw.Resolve()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already bound",
		"two forwards on one address should be caught before binding")
}

// Every bad spec should be reported together, so fixing a container
// environment does not take one deploy per mistake.
func TestResolveReportsEveryProblem(t *testing.T) {
	_, raw := newTestCommand()
	raw.forwards = []string{
		"http://70000=https://a.internal",
		"gopher://8081=https://b.internal",
	}

	_, err := raw.Resolve()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
	assert.Contains(t, err.Error(), "unknown scheme")
}

func TestResolveSetupKeyFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	// The trailing newline mirrors what a mounted secret usually contains.
	require.NoError(t, os.WriteFile(path, []byte("A1B2C3D4-SETUP-KEY\n"), 0o600))

	_, raw := newTestCommand()
	raw.forwards = []string{"http://8080=https://a.internal"}
	raw.setupKey = "file:" + path

	cfg, err := raw.Resolve()

	require.NoError(t, err)
	assert.Equal(t, "A1B2C3D4-SETUP-KEY", cfg.SetupKey, "a mounted secret should be trimmed")
}

// Each port-0 forward gets its own OS-assigned port, so sharing the spec is
// not a collision.
func TestResolveAllowsSeveralEphemeralPorts(t *testing.T) {
	_, raw := newTestCommand()
	raw.forwards = []string{
		"http://0=https://a.internal",
		"http://0=https://b.internal",
	}

	cfg, err := raw.Resolve()

	require.NoError(t, err)
	assert.Len(t, cfg.Forwards, 2, "two ephemeral forwards should both be kept")
}

func TestResolveSetupKeyFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte("   \n"), 0o600))

	_, raw := newTestCommand()
	raw.forwards = []string{"http://8080=https://a.internal"}
	raw.setupKey = "file:" + path

	_, err := raw.Resolve()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty",
		"an empty secret should fail rather than fall back to interactive login")
}

func TestResolveSetupKeyFileMissing(t *testing.T) {
	_, raw := newTestCommand()
	raw.forwards = []string{"http://8080=https://a.internal"}
	raw.setupKey = "file:" + filepath.Join(t.TempDir(), "absent")

	_, err := raw.Resolve()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "setup key")
}

func TestStatePathsFollowStateDir(t *testing.T) {
	cfg := &Config{}
	assert.Empty(t, cfg.ConfigPath(), "an unset state dir should keep identity in memory")
	assert.Empty(t, cfg.StatePath())

	cfg.StateDir = "/var/lib/nblink"
	assert.Equal(t, filepath.Join("/var/lib/nblink", "config.json"), cfg.ConfigPath())
	assert.Equal(t, filepath.Join("/var/lib/nblink", "state.json"), cfg.StatePath())
}
