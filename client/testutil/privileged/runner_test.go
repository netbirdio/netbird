//go:build privileged && (linux || darwin)

// Package privileged provides a self-hosting harness that runs the repo's
// privileged-tagged test suite inside a --privileged --cap-add=NET_ADMIN
// container, so developers can exercise the root/system-mutating tests on a
// non-root host with a single `go test` invocation.
package privileged

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/ory/dockertest/v4"
)

// containerImage / containerTag match the image used by the CI privileged job
// (.github/workflows/golang-test-linux.yml, test_client_on_docker).
const (
	containerImage = "golang"
	containerTag   = "1.25-alpine"
)

const (
	containerWorkdir    = "/app"
	containerGoCache    = "/root/.cache/go-build"
	containerGoModCache = "/go/pkg/mod"
)

// alpinePackages are the build/runtime deps the privileged tests need, mirroring
// the CI container setup.
const alpinePackages = "ca-certificates iptables ip6tables dbus dbus-dev libpcap-dev build-base"

// privilegedTestPackages is the package list the suite runs, excluding the
// server-side trees and UI/upload helpers, matching the CI Docker job's filter.
const privilegedTestPackages = `go list -buildvcs=false ./... | grep -v -e /management -e /signal -e /relay -e /proxy -e /combined -e /client/ui -e /upload-server`

// testWriter forwards container output to the test log line by line.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.t.Log(line)
	}
	return len(p), nil
}

// TestRunPrivilegedSuiteInDocker spins up a privileged container, mounts the repo,
// and runs `go test -tags 'devcert privileged'` inside it. When already running
// inside that container (DOCKER_CI=true) it returns immediately so the real
// privileged tests in the suite execute in place instead of recursing.
func TestRunPrivilegedSuiteInDocker(t *testing.T) {
	if os.Getenv("DOCKER_CI") == "true" {
		t.Skip("inside privileged container, skipping container spawn; privileged tests run in place")
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	goCache, goModCache := hostGoCaches(t)

	// dockertest reads DOCKER_HOST; point it at the active context's socket when
	// the default one is absent (macOS Docker Desktop, Colima, OrbStack).
	if host := dockerHost(); host != "" {
		t.Setenv("DOCKER_HOST", host)
	}

	// NewPoolT registers container cleanup via t.Cleanup automatically.
	pool := dockertest.NewPoolT(t, "", dockertest.WithMaxWait(30*time.Minute))

	// Keep the container alive so the suite runs via Exec, which yields a clean
	// exit code (the v4 Resource API exposes no container wait/exit-code).
	resource := pool.RunT(t, containerImage,
		dockertest.WithTag(containerTag),
		dockertest.WithWorkingDir(containerWorkdir),
		dockertest.WithMounts([]string{
			repoRoot + ":" + containerWorkdir,
			goCache + ":" + containerGoCache,
			goModCache + ":" + containerGoModCache,
		}),
		dockertest.WithEnv([]string{
			"CGO_ENABLED=1",
			"CI=true",
			"DOCKER_CI=true",
			"CONTAINER=true",
			"GOCACHE=" + containerGoCache,
			"GOMODCACHE=" + containerGoModCache,
		}),
		dockertest.WithCmd([]string{"sleep", "infinity"}),
		dockertest.WithHostConfig(func(hc *container.HostConfig) {
			hc.Privileged = true
			hc.CapAdd = []string{"NET_ADMIN"}
		}),
		dockertest.WithoutReuse(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	result, err := resource.Exec(ctx, []string{"sh", "-c", buildTestScript()})
	if err != nil {
		t.Fatalf("run privileged suite in container: %v", err)
	}

	w := testWriter{t}
	_, _ = w.Write([]byte(result.StdOut))
	_, _ = w.Write([]byte(result.StdErr))

	if result.ExitCode != 0 {
		t.Fatalf("privileged test suite failed in container (exit code %d)", result.ExitCode)
	}
}

// findRepoRoot walks up from the test's working directory to the module root.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// dockerHost returns a DOCKER_HOST override when the default socket is missing.
// An empty result means the caller should leave DOCKER_HOST untouched (it is
// already set, or the default unix socket exists). When neither is present
// (common on macOS Docker Desktop, Colima and OrbStack, which use a per-user
// socket), it resolves the active docker context's endpoint.
func dockerHost() string {
	if os.Getenv("DOCKER_HOST") != "" {
		return ""
	}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return ""
	}

	out, err := exec.Command("docker", "context", "inspect", "-f", "{{.Endpoints.docker.Host}}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// hostGoCaches resolves the host GOCACHE/GOMODCACHE so the container reuses the
// existing build/module cache for speed.
func hostGoCaches(t *testing.T) (string, string) {
	t.Helper()
	return goEnv(t, "GOCACHE"), goEnv(t, "GOMODCACHE")
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command("go", "env", key)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("go env %s: %v", key, err)
	}
	return strings.TrimSpace(out.String())
}

// buildTestScript builds the in-container command. PRIV_PKGS overrides the package
// list (default: the full filtered set); PRIV_RUN adds a -run test-name filter.
// Both empty reproduces the full privileged suite.
func buildTestScript() string {
	pkgs := privilegedTestPackages + " | xargs"
	if p := os.Getenv("PRIV_PKGS"); p != "" {
		pkgs = "echo " + p + " | xargs"
	}

	runFilter := ""
	if r := os.Getenv("PRIV_RUN"); r != "" {
		runFilter = "-run '" + r + "' "
	}

	return fmt.Sprintf(
		"apk update >/dev/null && apk add --no-cache %s >/dev/null && %s go test -buildvcs=false -tags 'devcert privileged' %s-v -timeout 20m -p 1",
		alpinePackages, pkgs, runFilter,
	)
}
