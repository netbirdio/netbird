//go:build e2e

package harness

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

const (
	clientDockerfile = "e2e/harness/Dockerfile.client"
	// defaultClientImage is the local tag the client is built under from
	// clientDockerfile. Override with NB_E2E_CLIENT_IMAGE: a value with a "/" is
	// pulled as a published image; a bare tag is built under that name.
	defaultClientImage = "netbird-client:e2e"
	clientAlias        = "client"
	curlImage          = "curlimages/curl:latest"
)

// Client is a running NetBird client container joined to the combined server.
type Client struct {
	container testcontainers.Container
}

// StartClient builds the client image and runs it on the combined server's
// network, joining via the given setup key. The image entrypoint brings the
// daemon up automatically; callers wait for connectivity with WaitConnected /
// WaitProxyPeer.
func StartClient(ctx context.Context, c *Combined, setupKey string) (*Client, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	clientImage, err := resolveImage(ctx, root, "NB_E2E_CLIENT_IMAGE", defaultClientImage, clientDockerfile)
	if err != nil {
		return nil, err
	}

	req := testcontainers.ContainerRequest{
		Image:          clientImage,
		Networks:       []string{c.network.Name},
		NetworkAliases: map[string][]string{c.network.Name: {clientAlias}},
		Env: map[string]string{
			"NB_MANAGEMENT_URL": combinedExposedURL,
			"NB_SETUP_KEY":      setupKey,
			"NB_LOG_LEVEL":      "info",
			// Match the proxy: the combined relay is WebSocket-only, so the
			// client must use WS transport to keep a stable relay link to it.
			"NB_RELAY_TRANSPORT": "ws",
			// Lazy connections defer the peer dial until traffic flows, which
			// leaves `netbird status` at "0/N Connected" and starves
			// WaitProxyPeer. Force eager connections so the proxy peer shows
			// Connected as soon as the tunnel is up.
			"NB_LAZY_CONN": "false",
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.CapAdd = append(hc.CapAdd, "NET_ADMIN", "SYS_ADMIN", "SYS_RESOURCE")
		},
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start client container: %w", err)
	}
	return &Client{container: ctr}, nil
}

// Restart bounces the client connection (netbird down/up) so it pulls a fresh
// network map — the documented workaround for a freshly-joined client not yet
// seeing a synthesized agent-network service.
func (cl *Client) Restart(ctx context.Context) error {
	if _, _, err := cl.container.Exec(ctx, []string{"netbird", "down"}, tcexec.Multiplexed()); err != nil {
		return fmt.Errorf("netbird down: %w", err)
	}
	time.Sleep(2 * time.Second)
	code, reader, err := cl.container.Exec(ctx, []string{"netbird", "up"}, tcexec.Multiplexed())
	if err != nil {
		return fmt.Errorf("netbird up: %w", err)
	}
	if code != 0 {
		out, _ := io.ReadAll(reader)
		return fmt.Errorf("netbird up exited %d: %s", code, string(out))
	}
	return nil
}

// Status returns `netbird status` output from inside the client.
func (cl *Client) Status(ctx context.Context) (string, error) {
	code, reader, err := cl.container.Exec(ctx, []string{"netbird", "status"}, tcexec.Multiplexed())
	if err != nil {
		return "", err
	}
	out, _ := io.ReadAll(reader)
	if code != 0 {
		return string(out), fmt.Errorf("netbird status exited %d", code)
	}
	return string(out), nil
}

// WaitConnected polls until the client reports Management: Connected.
func (cl *Client) WaitConnected(ctx context.Context, timeout time.Duration) error {
	return cl.pollStatus(ctx, timeout, "Management: Connected")
}

// WaitProxyPeer polls until the client sees at least one connected peer — the
// proxy serving the agent-network endpoint. It requires ">=1 connected" rather
// than an exact "1/1" because proxy peers from earlier tests linger in the
// account as disconnected (each proxy container registers a fresh WireGuard key
// and the peer is not removed on teardown), so the count is e.g. "1/2". Only the
// live proxy can be connected, and the caller's subsequent chat is the real
// end-to-end assertion.
func (cl *Client) WaitProxyPeer(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		out, _ := cl.Status(ctx)
		last = out
		if connectedPeers(out) >= 1 {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("timed out waiting for a connected proxy peer; last status:\n%s", last)
}

// connectedPeers parses the "Peers count: X/Y Connected" line from `netbird
// status` and returns X (the connected count), or 0 when absent/unparseable.
func connectedPeers(status string) int {
	for _, line := range strings.Split(status, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "Peers count:")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		slash := strings.IndexByte(rest, '/')
		if slash <= 0 {
			return 0
		}
		n, err := strconv.Atoi(strings.TrimSpace(rest[:slash]))
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

func (cl *Client) pollStatus(ctx context.Context, timeout time.Duration, want string) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		out, _ := cl.Status(ctx)
		last = out
		if strings.Contains(out, want) {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %q; last status:\n%s", want, last)
}

// ResolveProxyIP resolves the agent-network endpoint to the proxy peer's
// NetBird IP from inside the client (via magic DNS).
func (cl *Client) ResolveProxyIP(ctx context.Context, endpoint string) (string, error) {
	code, reader, err := cl.container.Exec(ctx, []string{"getent", "hosts", endpoint}, tcexec.Multiplexed())
	if err != nil {
		return "", err
	}
	out, _ := io.ReadAll(reader)
	if code != 0 {
		return "", fmt.Errorf("getent hosts %s exited %d", endpoint, code)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("no address for %s", endpoint)
	}
	return fields[0], nil
}

// Wire shapes for Chat.
const (
	// WireChat is the OpenAI-compatible /v1/chat/completions shape.
	WireChat = "chat"
	// WireMessages is the Anthropic /v1/messages shape.
	WireMessages = "messages"
	// WireVertex is the Anthropic-on-Vertex rawPredict shape: the client posts
	// the full Vertex model path and the proxy mints the SA OAuth token.
	WireVertex = "vertex"
	// WireBedrock is the native AWS Bedrock InvokeModel shape: the model id
	// travels in the URL path (/model/{id}/invoke), not the body, so the proxy
	// routes by path. This is what a Bedrock SDK client sends and the shape the
	// model-allowlist guardrail must enforce.
	WireBedrock = "bedrock"
)

// Chat issues a chat-completion POST to the agent-network endpoint over the
// client's tunnel, returning the HTTP status and response body. kind selects
// the wire shape: WireChat (OpenAI) or WireMessages (Anthropic). A non-empty
// sessionID is sent as the universal x-session-id header the proxy records.
func (cl *Client) Chat(ctx context.Context, endpoint, proxyIP, kind, model, prompt, sessionID string) (int, string, error) {
	var path, body string
	var headers []string
	switch kind {
	case WireMessages:
		path = "/v1/messages"
		headers = []string{"anthropic-version: 2023-06-01"}
		body = fmt.Sprintf(`{"model":%q,"max_tokens":64,"messages":[{"role":"user","content":%q}]}`, model, prompt)
	default:
		path = "/v1/chat/completions"
		body = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, model, prompt)
	}
	return cl.post(ctx, endpoint, proxyIP, path, body, withSessionID(headers, sessionID))
}

// Vertex issues an Anthropic-on-Vertex rawPredict POST over the tunnel. Unlike
// Chat, the model is carried in the request path (project/region/model), so the
// proxy routes by path and mints the service-account OAuth token; the body uses
// the Vertex anthropic_version rather than a model field. A non-empty sessionID
// is sent as the universal x-session-id header the proxy records.
func (cl *Client) Vertex(ctx context.Context, endpoint, proxyIP, project, region, model, prompt, sessionID string) (int, string, error) {
	path := fmt.Sprintf("/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:rawPredict", project, region, model)
	body := fmt.Sprintf(`{"anthropic_version":"vertex-2023-10-16","max_tokens":64,"messages":[{"role":"user","content":%q}]}`, prompt)
	return cl.post(ctx, endpoint, proxyIP, path, body, withSessionID(nil, sessionID))
}

// Bedrock issues a native AWS Bedrock InvokeModel POST over the tunnel. The
// model id is carried in the request path (/model/{id}/invoke), so the proxy
// routes by path; the body uses the bedrock anthropic_version rather than a
// model field. A non-empty sessionID is sent as the universal x-session-id
// header the proxy records.
func (cl *Client) Bedrock(ctx context.Context, endpoint, proxyIP, model, prompt, sessionID string) (int, string, error) {
	path := "/model/" + model + "/invoke"
	body := fmt.Sprintf(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":64,"messages":[{"role":"user","content":%q}]}`, prompt)
	return cl.post(ctx, endpoint, proxyIP, path, body, withSessionID(nil, sessionID))
}

// withSessionID appends the x-session-id header when sessionID is non-empty.
func withSessionID(headers []string, sessionID string) []string {
	if sessionID == "" {
		return headers
	}
	return append(headers, "x-session-id: "+sessionID)
}

// post runs curl in a throwaway container sharing the client's network
// namespace so the request traverses the WireGuard tunnel, pinning the endpoint
// to the proxy IP. It returns the HTTP status and response body.
func (cl *Client) post(ctx context.Context, endpoint, proxyIP, path, body string, extraHeaders []string) (int, string, error) {
	url := "https://" + endpoint + path
	args := []string{
		"run", "--rm",
		"--network", "container:" + cl.container.GetContainerID(),
		curlImage,
		"-sk", "--connect-timeout", "5", "--max-time", "90",
		"--resolve", endpoint + ":443:" + proxyIP,
		"-o", "/dev/stderr", "-w", "%{http_code}",
		"-X", "POST", url,
		"-H", "Content-Type: application/json",
	}
	for _, h := range extraHeaders {
		args = append(args, "-H", h)
	}
	args = append(args, "--data", body)
	cmd := exec.CommandContext(ctx, "docker", args...)
	// -w writes the status code to stdout; -o /dev/stderr writes the body to
	// stderr so we can capture both separately.
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return 0, stderr.String(), fmt.Errorf("curl through tunnel: %w", err)
	}

	code := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(stdout.String()), "%d", &code)
	return code, stderr.String(), nil
}

// Logs returns the client container logs, for diagnostics on failure.
func (cl *Client) Logs(ctx context.Context) string {
	return containerLogs(ctx, cl.container)
}

// Terminate stops the client container.
func (cl *Client) Terminate(ctx context.Context) error {
	if cl.container == nil {
		return nil
	}
	return cl.container.Terminate(ctx)
}

// containerLogs reads up to 256 KiB of a container's logs for diagnostics.
func containerLogs(ctx context.Context, c testcontainers.Container) string {
	if c == nil {
		return ""
	}
	r, err := c.Logs(ctx)
	if err != nil {
		return fmt.Sprintf("<logs error: %v>", err)
	}
	defer r.Close()
	b, _ := io.ReadAll(io.LimitReader(r, 256<<10))
	return string(b)
}
