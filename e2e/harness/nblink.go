//go:build e2e

package harness

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	nblinkDockerfile = "e2e/harness/Dockerfile.nblink"
	// defaultNBLinkImage is the local tag nblink is built under from
	// nblinkDockerfile. Override with NB_E2E_NBLINK_IMAGE: a value with a "/"
	// is pulled as a published image; a bare tag is built under that name.
	defaultNBLinkImage = "netbird-nblink:e2e"
	nblinkAlias        = "nblink"

	// NBLinkPort is the loopback port every forwarder in this suite listens
	// on. Tests reach it from a sidecar container sharing the forwarder's
	// network namespace, so loopback is enough and --allow-public-bind stays
	// off — the default an operator gets.
	NBLinkPort = 8080

	// nblinkCAPath is where the proxy's self-signed cert is mounted. nblink
	// verifies its upstream like any Go HTTP client, so without this the
	// forward fails the TLS handshake rather than reaching the endpoint.
	nblinkCAPath = "/etc/nblink/upstream-ca.crt"

	// nblinkReadyLog is the line startForwards writes once the overlay session
	// is up and every forward is bound.
	nblinkReadyLog = "over the overlay"

	// nblinkKeyPath is where WithNBLinkSetupKeyFile places the setup key.
	nblinkKeyPath = "/run/secrets/nb_setup_key"
	// nblinkKeyMode is root-owned and readable by group 0 only, the ownership
	// the README tells operators a key file needs for UID 65532:0 to read it.
	nblinkKeyMode = 0o440

	// nblinkStateDir is the state directory both images create, owned by
	// 65532:0, so a volume mounted over it inherits that ownership.
	nblinkStateDir = "/var/lib/nblink"
)

// NBLink is a running nblink container: a NetBird peer in userspace mode
// forwarding a local port to an upstream reached inside the tunnel.
type NBLink struct {
	container testcontainers.Container
	name      string
	port      int
}

// nblinkOptions is what the NBLinkOption values assemble.
type nblinkOptions struct {
	name        string
	port        int
	extra       []string
	keyAsFile   bool
	stateVolume string
}

// NBLinkOption adjusts how StartNBLink runs the forwarder.
type NBLinkOption func(*nblinkOptions)

// WithNBLinkName names the forwarder, setting both its network alias and its
// container hostname. The hostname is what the peer registers under, so it is
// the name the peer appears beneath in the peers API.
//
// Required to run a second forwarder against the same server: the default name
// is shared and two containers cannot hold one alias on a network.
func WithNBLinkName(name string) NBLinkOption {
	return func(o *nblinkOptions) { o.name = name }
}

// WithNBLinkForwards adds forwards to the one StartNBLink is given. They are
// passed in the same comma-separated NB_FORWARD, so one process serves all of
// them over one session.
func WithNBLinkForwards(specs ...string) NBLinkOption {
	return func(o *nblinkOptions) { o.extra = append(o.extra, specs...) }
}

// WithNBLinkSetupKeyFile delivers the setup key as a file in the container and
// points NB_SETUP_KEY at it with the file: prefix, instead of putting the key
// itself in the environment.
func WithNBLinkSetupKeyFile() NBLinkOption {
	return func(o *nblinkOptions) { o.keyAsFile = true }
}

// WithNBLinkStateVolume mounts the named Docker volume as the state directory
// and sets NB_STATE_DIR, so the peer identity outlives the container. The
// volume is created on first use; RemoveDockerVolume deletes it.
func WithNBLinkStateVolume(volume string) NBLinkOption {
	return func(o *nblinkOptions) { o.stateVolume = volume }
}

// StartNBLink builds the nblink image and runs it on the combined server's
// network, joining with the given setup key and serving one HTTP forward.
//
// forward is a complete spec (scheme://[host:]port=upstream). caCertPath is a
// PEM file on the host holding the upstream's certificate, mounted in and
// pointed at with SSL_CERT_FILE; pass "" when the upstream needs no extra
// trust.
//
// The container is granted no capabilities and no TUN device. That is the
// assertion, not an oversight: nblink that needed either would not be able to
// run where it claims to.
func StartNBLink(ctx context.Context, c *Combined, setupKey, forward, caCertPath string, opts ...NBLinkOption) (*NBLink, error) {
	o := nblinkOptions{name: nblinkAlias, port: NBLinkPort}
	for _, opt := range opts {
		opt(&o)
	}

	image, err := nblinkImage(ctx)
	if err != nil {
		return nil, err
	}

	env := map[string]string{
		"NB_MANAGEMENT_URL": combinedExposedURL,
		"NB_SETUP_KEY":      setupKey,
		"NB_FORWARD":        strings.Join(append([]string{forward}, o.extra...), ","),
		"NB_HOSTNAME":       o.name,
		"NB_LOG_LEVEL":      "debug",
		// Match the agent and the proxy: the combined relay is WebSocket-only,
		// so the embedded client must use WS to hold a stable relay link.
		"NB_RELAY_TRANSPORT": "ws",
	}
	if caCertPath != "" {
		env["SSL_CERT_FILE"] = nblinkCAPath
	}
	var files []testcontainers.ContainerFile
	if o.keyAsFile {
		env["NB_SETUP_KEY"] = "file:" + nblinkKeyPath
		files = append(files, testcontainers.ContainerFile{
			Reader:            strings.NewReader(setupKey + "\n"),
			ContainerFilePath: nblinkKeyPath,
			FileMode:          nblinkKeyMode,
		})
	}
	if o.stateVolume != "" {
		env["NB_STATE_DIR"] = nblinkStateDir
	}

	req := testcontainers.ContainerRequest{
		Image: image,
		// The embedded client reports the container hostname to management, so
		// this is the name the peer is addressable by in the API.
		Hostname:       o.name,
		Networks:       []string{c.network.Name},
		NetworkAliases: map[string][]string{c.network.Name: {o.name}},
		Env:            env,
		Files:          files,
		HostConfigModifier: func(hc *container.HostConfig) {
			if caCertPath != "" {
				hc.Binds = append(hc.Binds, caCertPath+":"+nblinkCAPath+":ro")
			}
			if o.stateVolume != "" {
				hc.Mounts = append(hc.Mounts, mount.Mount{
					Type:   mount.TypeVolume,
					Source: o.stateVolume,
					Target: nblinkStateDir,
				})
			}
		},
		// The session has 90s of its own to come up, so the wait has to outlast
		// that or a slow handshake reads as a missing log line.
		WaitingFor: wait.ForLog(nblinkReadyLog).WithStartupTimeout(150 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start nblink container: %w", err)
	}
	return &NBLink{container: ctr, name: o.name, port: o.port}, nil
}

func nblinkImage(ctx context.Context) (string, error) {
	root, err := repoRoot(ctx)
	if err != nil {
		return "", err
	}
	return resolveImage(ctx, root, "NB_E2E_NBLINK_IMAGE", defaultNBLinkImage, nblinkDockerfile)
}

// Hostname returns the container hostname the embedded client reports to
// management — the name the registered peer appears under in the peers API.
func (n *NBLink) Hostname() string {
	return n.name
}

// Post issues a JSON POST to the forwarder's primary listener and returns the
// HTTP status and response body.
func (n *NBLink) Post(ctx context.Context, path, body string, extraHeaders []string) (int, string, error) {
	return n.do(ctx, n.port, http.MethodPost, path, body, extraHeaders)
}

// PostOn issues a JSON POST to the forwarder's listener on port, for a forward
// added with WithNBLinkForwards.
func (n *NBLink) PostOn(ctx context.Context, port int, path, body string, extraHeaders []string) (int, string, error) {
	return n.do(ctx, port, http.MethodPost, path, body, extraHeaders)
}

// Get issues a GET to the forwarder's primary listener.
func (n *NBLink) Get(ctx context.Context, path string, extraHeaders []string) (int, string, error) {
	return n.do(ctx, n.port, http.MethodGet, path, "", extraHeaders)
}

// ChatPath and ChatBody are the request the forwarder is driven with. They are
// exported so a test can send the very same request with one header changed
// and attribute the difference in the answer to that header alone.
const ChatPath = "/v1/chat/completions"

// ChatBody builds an OpenAI-shaped chat completion request body.
func ChatBody(model, prompt string) string {
	return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, model, prompt)
}

// Chat issues an OpenAI-shaped chat completion to the forwarder, which proxies
// it to the agent-network endpoint over the tunnel. A non-empty sessionID is
// sent as the x-session-id header the proxy records.
func (n *NBLink) Chat(ctx context.Context, model, prompt, sessionID string) (int, string, error) {
	return n.Post(ctx, ChatPath, ChatBody(model, prompt), withSessionID(nil, sessionID))
}

// do runs curl in a throwaway container sharing the forwarder's network
// namespace, so the request arrives on its loopback listener exactly as a
// process running beside it would send one.
//
// Nothing here pins or rewrites Host: the loopback listener refuses a Host
// that is not its own, and a test that papered over that would stop covering
// it. Callers that want a foreign Host pass it in extraHeaders on purpose.
func (n *NBLink) do(ctx context.Context, port int, method, path, body string, extraHeaders []string) (int, string, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
	args := []string{
		"run", "--rm",
		"--network", "container:" + n.container.GetContainerID(),
		curlImage,
		"-s", "--connect-timeout", "5", "--max-time", "90",
		"-o", "/dev/stderr", "-w", "%{http_code}",
		"-X", method, url,
		"-H", "Content-Type: application/json",
	}
	for _, h := range extraHeaders {
		args = append(args, "-H", h)
	}
	if body != "" {
		args = append(args, "--data", body)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	// -w writes the status to stdout, -o /dev/stderr the body to stderr, so
	// the two come back separately.
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return 0, stderr.String(), fmt.Errorf("curl through nblink: %w", err)
	}

	code := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(stdout.String()), "%d", &code)
	return code, stderr.String(), nil
}

// Logs returns the nblink container logs, for diagnostics on failure.
func (n *NBLink) Logs(ctx context.Context) string {
	return containerLogs(ctx, n.container)
}

// Terminate stops the nblink container.
func (n *NBLink) Terminate(ctx context.Context) error {
	if n.container == nil {
		return nil
	}
	return n.container.Terminate(ctx)
}

// NBLinkCheckResult is what a --check run printed and how it exited.
type NBLinkCheckResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// RunNBLinkCheck runs the nblink image with --check and the given environment.
// The container gets no network at all, so a run that tried to reach
// management would fail rather than quietly succeed.
func RunNBLinkCheck(ctx context.Context, env map[string]string) (NBLinkCheckResult, error) {
	image, err := nblinkImage(ctx)
	if err != nil {
		return NBLinkCheckResult{}, err
	}

	args := []string{"run", "--rm", "--network", "none"}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, image, "--check")

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	res := NBLinkCheckResult{}
	err = cmd.Run()
	res.Stdout, res.Stderr = stdout.String(), stderr.String()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("run nblink --check: %w", err)
	}
	return res, nil
}

// RemoveDockerVolume deletes a volume created by WithNBLinkStateVolume.
func RemoveDockerVolume(ctx context.Context, volume string) error {
	if out, err := exec.CommandContext(ctx, "docker", "volume", "rm", "-f", volume).CombinedOutput(); err != nil {
		return fmt.Errorf("remove volume %s: %w: %s", volume, err, out)
	}
	return nil
}
