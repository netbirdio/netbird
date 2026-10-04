package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/version"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := rootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// A forward spec that lost its --forward is the usual stray argument, and it
// must not start a forwarder with whatever else was configured.
func TestRejectsPositionalArguments(t *testing.T) {
	_, err := execute(t, "--check", "--forward", "http://8080=https://grafana.internal", "http://9090=https://prometheus.internal")
	require.Error(t, err, "a positional argument must be refused")
	assert.Contains(t, err.Error(), "unknown command", "the error must point at the stray argument")
}

func TestRejectsInvalidEnvironmentValue(t *testing.T) {
	t.Setenv("NB_ALLOW_PUBLIC_BIND", "maybe")
	_, err := execute(t, "--check", "--forward", "http://8080=https://grafana.internal")
	require.Error(t, err, "an unparseable environment value must stop the start")
	assert.Contains(t, err.Error(), "NB_ALLOW_PUBLIC_BIND", "the error must name the variable")
}

func TestEnvironmentConfiguresAFullCheck(t *testing.T) {
	t.Setenv("NB_FORWARD", "http://8080=https://grafana.internal,http://0.0.0.0:9090=https://prometheus.internal")
	t.Setenv("NB_ALLOW_PUBLIC_BIND", "true")
	t.Setenv("NB_CHECK", "true")
	_, err := execute(t)
	assert.NoError(t, err, "a complete environment configuration must pass the check without flags")
}

func TestRequiresAForward(t *testing.T) {
	_, err := execute(t, "--check")
	require.Error(t, err, "a run with no forward must be refused")
	assert.Contains(t, err.Error(), "NB_FORWARD", "the error must name the environment variable too")
}

func TestPrintsVersion(t *testing.T) {
	out, err := execute(t, "--version")
	require.NoError(t, err)
	assert.Contains(t, out, version.NetbirdVersion(), "--version must print the build version")
}
