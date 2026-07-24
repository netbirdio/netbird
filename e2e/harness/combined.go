//go:build e2e

package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/netbirdio/netbird/shared/management/client/rest"
)

const (
	combinedDockerfile = "combined/Dockerfile.multistage"
	// defaultCombinedImage is the local tag the combined server is built under
	// from combinedDockerfile, so the e2e exercises this branch's code. Override
	// with NB_E2E_COMBINED_IMAGE: a value containing a "/" is pulled as a
	// published image; a bare tag is built under that name instead.
	defaultCombinedImage = "netbird-combined:e2e"
	combinedHTTPPort     = "8080/tcp"

	// combinedAlias is the combined server's network alias AND the deployment
	// domain. The working manual setup uses a single NETBIRD_DOMAIN for the
	// management exposed address, the proxy domain, and the agent-network
	// cluster — so we mirror that: peers reach management/signal/relay at this
	// name, the proxy registers this as its cluster, and the agent-network
	// endpoint is <subdomain>.<combinedAlias>.
	combinedAlias      = "netbird.local"
	combinedExposedURL = "http://" + combinedAlias + ":8080"

	// containerIssuer is the embedded IdP issuer, used only for internal JWT
	// validation (peers authenticate with setup keys / proxy tokens, not OIDC),
	// so the in-container localhost address is fine.
	containerIssuer = "http://localhost:8080/oauth2"
)

// Combined is a running combined NetBird server (management + signal + relay +
// STUN + embedded IdP) plus the connection details tests need. It owns the
// shared docker network that the proxy and client containers join.
type Combined struct {
	container testcontainers.Container
	network   *testcontainers.DockerNetwork
	// BaseURL is the host-reachable management API root, e.g. http://127.0.0.1:51234.
	BaseURL string
	// PAT is the admin Personal Access Token minted via Bootstrap.
	PAT string

	api     *rest.Client
	workDir string
}

// StartCombined builds the combined server from its multistage Dockerfile and
// boots it with setup-PAT enabled on a fresh shared network, returning once the
// API is serving. The caller still owns minting the admin PAT via Bootstrap.
func StartCombined(ctx context.Context) (*Combined, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}

	combinedImage, err := resolveImage(ctx, root, "NB_E2E_COMBINED_IMAGE", defaultCombinedImage, combinedDockerfile)
	if err != nil {
		return nil, err
	}

	net, err := network.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create shared network: %w", err)
	}

	// Work dir under /tmp so Docker Desktop file sharing (which excludes
	// macOS's /var/folders TMPDIR) can bind-mount it.
	workDir, err := os.MkdirTemp("/tmp", "nb-e2e-combined-*")
	if err != nil {
		_ = net.Remove(ctx)
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	cfg := fmt.Sprintf(combinedConfigYAML, combinedExposedURL, containerIssuer)
	if err := os.WriteFile(filepath.Join(workDir, "config.yaml"), []byte(cfg), 0o644); err != nil { //nolint:gosec // non-secret config, bind-mounted and read by the container
		_ = net.Remove(ctx)
		return nil, fmt.Errorf("write combined config: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(workDir, "data"), 0o755); err != nil {
		_ = net.Remove(ctx)
		return nil, fmt.Errorf("create datadir: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:          combinedImage,
		ExposedPorts:   []string{combinedHTTPPort},
		Networks:       []string{net.Name},
		NetworkAliases: map[string][]string{net.Name: {combinedAlias}},
		Env: map[string]string{
			"NB_SETUP_PAT_ENABLED": "true",
			// Skip the GeoLite DB download — it blocks startup and agent-network
			// ingest doesn't use geolocation.
			"NB_DISABLE_GEOLOCATION": "true",
		},
		Cmd: []string{"--config", "/nb/config.yaml"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, workDir+":/nb")
		},
		WaitingFor: wait.ForHTTP("/api/instance").
			WithPort(combinedHTTPPort).
			WithStatusCodeMatcher(func(status int) bool { return status == 200 }).
			WithStartupTimeout(120 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		_ = net.Remove(ctx)
		return nil, fmt.Errorf("start combined container: %w", err)
	}

	host, err := c.Host(ctx)
	if err != nil {
		_ = c.Terminate(ctx)
		_ = net.Remove(ctx)
		return nil, fmt.Errorf("container host: %w", err)
	}
	mapped, err := c.MappedPort(ctx, nat.Port(combinedHTTPPort))
	if err != nil {
		_ = c.Terminate(ctx)
		_ = net.Remove(ctx)
		return nil, fmt.Errorf("mapped port: %w", err)
	}

	return &Combined{
		container: c,
		network:   net,
		BaseURL:   fmt.Sprintf("http://%s:%s", host, mapped.Port()),
		workDir:   workDir,
	}, nil
}

// resolveImage returns the image to run for a component. By default it builds
// the image from the repo Dockerfile under localTag, so the e2e exercises the
// branch's code. The env override changes this: a value containing a "/" is a
// registry reference that testcontainers pulls (e.g. to test a published
// release); a bare tag is built under that name instead.
func resolveImage(ctx context.Context, root, envKey, localTag, dockerfile string) (string, error) {
	if v := os.Getenv(envKey); v != "" {
		if strings.Contains(v, "/") {
			return v, nil
		}
		localTag = v
	}
	if err := buildImage(ctx, root, dockerfile, localTag); err != nil {
		return "", err
	}
	return localTag, nil
}

// buildImage builds an image from a repo Dockerfile via buildx with BuildKit, so
// the Dockerfile cache mounts are honored and unchanged layers are reused. The
// result is loaded into the docker image store so testcontainers runs it by tag.
// When NB_E2E_BUILDX_CACHE names a directory (CI, with a container-driver
// builder from docker/setup-buildx-action), layer cache is read from and written
// to it as a local cache so actions/cache can persist it across runs; the Go
// compile itself still re-runs, as BuildKit mount caches can't be exported.
func buildImage(ctx context.Context, root, dockerfile, tag string) error {
	args := []string{"buildx", "build", "-f", dockerfile, "-t", tag, "--load"}
	if dir := os.Getenv("NB_E2E_BUILDX_CACHE"); dir != "" {
		args = append(args,
			"--cache-from", "type=local,src="+dir,
			"--cache-to", "type=local,dest="+dir+",mode=max",
		)
	}
	args = append(args, ".")

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build image %s: %w\n%s", tag, err, string(out))
	}
	return nil
}

// CreateProxyTokenCLI mints a proxy access token via the server's `token
// create` CLI inside the container — the same path the manual install uses.
// This yields a GLOBAL (account-less) token, so the proxy serves the whole
// cluster (SynthesizeServicesForCluster); an account-scoped REST token instead
// drives the per-account path. Returns the plaintext token.
func (c *Combined) CreateProxyTokenCLI(ctx context.Context, name string) (string, error) {
	code, reader, err := c.container.Exec(ctx,
		[]string{"/go/bin/netbird-server", "token", "create", "--name", name, "--config", "/nb/config.yaml"},
		tcexec.Multiplexed())
	if err != nil {
		return "", fmt.Errorf("exec token create: %w", err)
	}
	out, _ := io.ReadAll(reader)
	if code != 0 {
		return "", fmt.Errorf("token create exited %d: %s", code, string(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Token:") {
			tok := strings.TrimSpace(strings.TrimPrefix(line, "Token:"))
			if tok != "" {
				return tok, nil
			}
		}
	}
	return "", fmt.Errorf("token not found in CLI output: %s", string(out))
}

// SnapshotStoreDB copies the management server's sqlite store (and its
// WAL/SHM sidecars when present) out of the bind-mounted data dir into
// dstDir, returning the path of the copied database. Tests open the copy
// instead of the live file so a concurrent management write can never lock
// or corrupt the read.
func (c *Combined) SnapshotStoreDB(dstDir string) (string, error) {
	src := filepath.Join(c.workDir, "data", "store.db")
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("management store not found at %s: %w", src, err)
	}
	dst := filepath.Join(dstDir, "store.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(src + suffix)
		if err != nil {
			if os.IsNotExist(err) && suffix != "" {
				continue // sidecar only exists in WAL mode
			}
			return "", fmt.Errorf("read %s: %w", src+suffix, err)
		}
		if err := os.WriteFile(dst+suffix, data, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", dst+suffix, err)
		}
	}
	return dst, nil
}

// Logs returns the combined server container logs, for diagnostics.
func (c *Combined) Logs(ctx context.Context) string {
	return containerLogs(ctx, c.container)
}

// Terminate stops the container, removes the shared network, and cleans the
// work dir.
func (c *Combined) Terminate(ctx context.Context) error {
	var err error
	if c.container != nil {
		err = c.container.Terminate(ctx)
	}
	if c.network != nil {
		_ = c.network.Remove(ctx)
	}
	if c.workDir != "" {
		_ = os.RemoveAll(c.workDir)
	}
	return err
}
