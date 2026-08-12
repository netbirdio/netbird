//go:build e2e

package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The options exist so a suite can ask for a deployment this harness would not
// otherwise give it. What they configure is a container environment and a config
// file, both assembled before anything is started, so they are checkable without
// Docker — which is the point: a wiring mistake here would otherwise only show up
// as a puzzling failure minutes into a container run.

func TestCombinedEnvGeolocation(t *testing.T) {
	var off combinedOptions
	if got := combinedEnv(off)["NB_DISABLE_GEOLOCATION"]; got != "true" {
		t.Errorf("geolocation should be off by default, NB_DISABLE_GEOLOCATION = %q", got)
	}

	var on combinedOptions
	WithGeolocation()(&on)
	if _, set := combinedEnv(on)["NB_DISABLE_GEOLOCATION"]; set {
		t.Error("WithGeolocation must leave NB_DISABLE_GEOLOCATION unset, so the server downloads the database")
	}
	if combinedEnv(on)["NB_SETUP_PAT_ENABLED"] != "true" {
		t.Error("the setup PAT must stay enabled whatever else is configured; Bootstrap depends on it")
	}
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
			if !strings.Contains(cfg, tc.want) {
				t.Errorf("config should contain %q, got:\n%s", tc.want, cfg)
			}
			// The issuer is the last verb; a mis-ordered argument list would put
			// the boolean here instead and the server would fail to start.
			if !strings.Contains(cfg, `issuer: "`+containerIssuer+`"`) {
				t.Errorf("issuer not rendered, got:\n%s", cfg)
			}
		})
	}
}

func TestWithServerEnvOverrides(t *testing.T) {
	var o combinedOptions
	WithServerEnv(map[string]string{"NB_LOG_LEVEL": "debug"})(&o)
	WithServerEnv(map[string]string{"NB_SETUP_PAT_ENABLED": "false"})(&o)

	env := combinedEnv(o)
	if env["NB_LOG_LEVEL"] != "debug" {
		t.Errorf("added variable missing, NB_LOG_LEVEL = %q", env["NB_LOG_LEVEL"])
	}
	if env["NB_SETUP_PAT_ENABLED"] != "false" {
		t.Errorf("a suite must be able to override a default, NB_SETUP_PAT_ENABLED = %q", env["NB_SETUP_PAT_ENABLED"])
	}
}

// Two agents on one network cannot share an alias, so the name has to reach both
// the alias and the hostname. The hostname is the one management records, so it is
// also what the peer is addressable by through the API.
func TestWithClientName(t *testing.T) {
	o := clientOptions{name: clientAlias}
	if o.name != "client" {
		t.Fatalf("unexpected default client name %q", o.name)
	}

	WithClientName("peer2")(&o)
	if o.name != "peer2" {
		t.Errorf("WithClientName did not take, name = %q", o.name)
	}
}

// repoRoot has to recognise this module rather than merely finding a go.mod, or a
// suite in another module gets its own root and a build context without the
// component Dockerfiles in it.
func TestIsModule(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(other, []byte("module example.com/other\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if isModule(other, modulePath) {
		t.Error("another module's go.mod must not be taken for this repo")
	}

	ours := filepath.Join(dir, "ours.mod")
	if err := os.WriteFile(ours, []byte("// a comment\n\nmodule "+modulePath+"\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isModule(ours, modulePath) {
		t.Error("this repo's go.mod was not recognised")
	}

	if isModule(filepath.Join(dir, "absent.mod"), modulePath) {
		t.Error("a missing go.mod must not report a match")
	}
}

// Running from inside the repo, repoRoot finds it by walking up — the module
// lookup is only the fallback, and this asserts the walk still wins so an
// in-repo run never depends on the module cache.
func TestRepoRootFindsThisRepo(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	if !isModule(filepath.Join(root, "go.mod"), modulePath) {
		t.Errorf("repoRoot returned %s, which is not this module", root)
	}
	for _, f := range []string{combinedDockerfile, clientDockerfile} {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Errorf("%s is not present under the reported root %s: %v", f, root, err)
		}
	}
}
