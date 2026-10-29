//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// modulePath is this module, used both to recognise the repo when walking up
// from the working directory and to locate it when the suite lives elsewhere.
const modulePath = "github.com/netbirdio/netbird"

// repoRoot returns the directory the component Dockerfiles are built from.
//
// Walking up from the working directory finds it for any test inside this repo,
// no matter which package it runs from. A suite in another module gets a
// different answer that way — its own module root, where combined/Dockerfile
// does not exist — so the ancestor has to be this module and not merely some
// module. When it is not, the build context is the extracted module directory of
// whichever version that suite depends on, which is the right one: the server it
// tests against is then built from the same revision as the client library it
// was compiled with.
func repoRoot(ctx context.Context) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if isModule(filepath.Join(dir, "go.mod"), modulePath) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return moduleDir(ctx, modulePath)
}

// isModule reports whether the go.mod at path declares the given module.
func isModule(path, want string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest) == want
		}
	}
	return false
}

// moduleDir asks the go tool where a module's source is, which for a dependent
// module is its extracted copy in the module cache. The cache is read-only, and
// a Docker build context is only ever read.
//
// -mod=readonly is required rather than cosmetic. A caller that vendors its
// dependencies puts the go command in automatic vendor mode, where this lookup
// succeeds with an EMPTY directory — vendor/ holds packages, not module source,
// so there is nothing to report. Asking in readonly mode resolves against the
// module graph instead, which answers for both a cached module and a local
// replacement, and neither writes to go.mod.
func moduleDir(ctx context.Context, module string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-f", "{{.Dir}}", module)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locate %s: %w", module, err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("locate %s: the go tool reported no directory; run `go mod download %s`", module, module)
	}
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("locate %s: %w", module, err)
	}
	return dir, nil
}
