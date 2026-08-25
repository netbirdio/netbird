//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The options exist so a suite can ask for a deployment this harness would not
// otherwise give it. What they configure is a container environment and a config
// file, both assembled before anything is started, so they are checkable without
// Docker — which is the point: a wiring mistake here would otherwise only show up
// as a puzzling failure minutes into a container run.

func TestCombinedEnvGeolocation(t *testing.T) {
	var off combinedOptions
	assert.Equal(t, "true", combinedEnv(off)["NB_DISABLE_GEOLOCATION"],
		"geolocation should be off by default")

	var on combinedOptions
	WithGeolocation()(&on)
	assert.NotContains(t, combinedEnv(on), "NB_DISABLE_GEOLOCATION",
		"WithGeolocation must leave NB_DISABLE_GEOLOCATION unset, so the server downloads the database")
	assert.Equal(t, "true", combinedEnv(on)["NB_SETUP_PAT_ENABLED"],
		"the setup PAT must stay enabled whatever else is configured; Bootstrap depends on it")
}

// The config file carries the same decision as the environment variable, and the
// server needs both to agree: disableGeoliteUpdate suppresses the download even
// when geolocation itself is enabled.
func TestCombinedConfigGeolocation(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []CombinedOption
		want string
	}{
		{name: "default", want: "disableGeoliteUpdate: true"},
		{name: "with geolocation", opts: []CombinedOption{WithGeolocation()}, want: "disableGeoliteUpdate: false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var o combinedOptions
			for _, opt := range tc.opts {
				opt(&o)
			}
			cfg := fmt.Sprintf(combinedConfigYAML, combinedExposedURL, !o.geolocation, containerIssuer)
			assert.Contains(t, cfg, tc.want, "geolocation not rendered as expected")
			// The issuer is the last verb; a mis-ordered argument list would put
			// the boolean here instead and the server would fail to start.
			assert.Contains(t, cfg, `issuer: "`+containerIssuer+`"`, "issuer not rendered")
		})
	}
}

func TestWithServerEnvOverrides(t *testing.T) {
	var o combinedOptions
	WithServerEnv(map[string]string{"NB_LOG_LEVEL": "debug"})(&o)
	WithServerEnv(map[string]string{"NB_SETUP_PAT_ENABLED": "false"})(&o)

	env := combinedEnv(o)
	assert.Equal(t, "debug", env["NB_LOG_LEVEL"], "added variable missing")
	assert.Equal(t, "false", env["NB_SETUP_PAT_ENABLED"], "a suite must be able to override a default")
}

// Two agents on one network cannot share an alias, so the name has to reach both
// the alias and the hostname. The hostname is the one management records, so it is
// also what the peer is addressable by through the API.
func TestWithClientName(t *testing.T) {
	o := clientOptions{name: clientAlias}
	require.Equal(t, "client", o.name, "unexpected default client name")

	WithClientName("peer2")(&o)
	assert.Equal(t, "peer2", o.name, "WithClientName did not take")
}

// repoRoot has to recognise this module rather than merely finding a go.mod, or a
// suite in another module gets its own root and a build context without the
// component Dockerfiles in it.
func TestIsModule(t *testing.T) {
	dir := t.TempDir()

	other := filepath.Join(dir, "go.mod")
	require.NoError(t, os.WriteFile(other, []byte("module example.com/other\n\ngo 1.25\n"), 0o600))
	assert.False(t, isModule(other, modulePath), "another module's go.mod must not be taken for this repo")

	ours := filepath.Join(dir, "ours.mod")
	require.NoError(t, os.WriteFile(ours, []byte("// a comment\n\nmodule "+modulePath+"\n\ngo 1.25\n"), 0o600))
	assert.True(t, isModule(ours, modulePath), "this repo's go.mod was not recognised")

	assert.False(t, isModule(filepath.Join(dir, "absent.mod"), modulePath),
		"a missing go.mod must not report a match")
}

// Running from inside the repo, repoRoot finds it by walking up — the module
// lookup is only the fallback, and this asserts the walk still wins so an in-repo
// run never depends on the module cache.
func TestRepoRootFindsThisRepo(t *testing.T) {
	root, err := repoRoot(context.Background())
	require.NoError(t, err)
	assert.True(t, isModule(filepath.Join(root, "go.mod"), modulePath),
		"repoRoot returned %s, which is not this module", root)

	for _, f := range []string{combinedDockerfile, clientDockerfile} {
		_, err := os.Stat(filepath.Join(root, f))
		assert.NoError(t, err, "%s is not present under the reported root %s", f, root)
	}
}

// A caller that vendors its dependencies puts the go command in automatic vendor
// mode, where `go list -m -f {{.Dir}}` succeeds and reports an EMPTY directory:
// vendor/ holds packages, not module source. Without -mod=readonly the lookup
// would come back empty and the harness would report a missing module for a
// dependency that is present.
func TestModuleDirResolvesUnderVendorMode(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	ctx := context.Background()

	base := t.TempDir()
	dep := filepath.Join(base, "dep")
	main := filepath.Join(base, "main")
	require.NoError(t, os.MkdirAll(dep, 0o750))
	require.NoError(t, os.MkdirAll(main, 0o750))

	// A local replacement rather than a real dependency, so this needs no network.
	require.NoError(t, os.WriteFile(filepath.Join(dep, "go.mod"),
		[]byte("module example.com/dep\n\ngo 1.25\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dep, "dep.go"),
		[]byte("package dep\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(main, "go.mod"),
		[]byte("module example.com/main\n\ngo 1.25\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep v0.0.0 => ../dep\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(main, "main.go"),
		[]byte("package main\n\nimport _ \"example.com/dep\"\n\nfunc main() {}\n"), 0o600))

	t.Chdir(main)
	vendor := exec.CommandContext(ctx, "go", "mod", "vendor")
	out, err := vendor.CombinedOutput()
	require.NoError(t, err, "go mod vendor: %s", out)

	dir, err := moduleDir(ctx, "example.com/dep")
	require.NoError(t, err, "the module must still resolve with a vendor directory present")
	assert.Equal(t, dep, dir, "resolved the wrong directory")
}

// A cancelled context has to stop the lookup rather than leaving the caller
// waiting on a subprocess it has already given up on.
func TestModuleDirHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := moduleDir(ctx, modulePath)
	assert.ErrorIs(t, err, context.Canceled, "a cancelled context must stop the lookup")
}
