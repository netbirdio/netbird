//go:build e2e

package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// clientOptions is what the ClientOption values assemble.
type clientOptions struct {
	name string
}

// ClientOption adjusts how StartClient runs the agent.
type ClientOption func(*clientOptions)

// WithClientName names the agent, which sets both its network alias and its
// container hostname. The hostname matters beyond addressing: the agent reports
// it to management at registration, so it is the name the peer appears under in
// the API.
//
// Required to run more than one agent against the same server — the default name
// is shared, and two containers cannot hold the same alias on one network.
func WithClientName(name string) ClientOption {
	return func(o *clientOptions) { o.name = name }
}

// StartClient builds the client image and runs it on the combined server's
// network, joining via the given setup key. The image entrypoint brings the
// daemon up automatically; callers wait for connectivity with WaitConnected /
// WaitProxyPeer.
func StartClient(ctx context.Context, c *Combined, setupKey string, opts ...ClientOption) (*Client, error) {
	o := clientOptions{name: clientAlias}
	for _, opt := range opts {
		opt(&o)
	}

	root, err := repoRoot(ctx)
	if err != nil {
		return nil, err
	}
	clientImage, err := resolveImage(ctx, root, "NB_E2E_CLIENT_IMAGE", defaultClientImage, clientDockerfile)
	if err != nil {
		return nil, err
	}

	req := testcontainers.ContainerRequest{
		Image: clientImage,
		// The agent reports the container's hostname to management, so this is
		// the name the peer is addressable by in the API as well as on the
		// network. The entrypoint takes no hostname flag of its own.
		Hostname:       o.name,
		Networks:       []string{c.network.Name},
		NetworkAliases: map[string][]string{c.network.Name: {o.name}},
		Env: map[string]string{
			"NB_MANAGEMENT_URL": combinedExposedURL,
			"NB_SETUP_KEY":      setupKey,
			"NB_LOG_LEVEL":      "info",
			// Match the proxy: the combined relay is WebSocket-only, so the
			// client must use WS transport to keep a stable relay link to it.
			"NB_RELAY_TRANSPORT": "ws",
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

const (
	// curlExitCouldNotResolve is curl's exit code for a DNS resolution failure, distinct from connection-level failures.
	curlExitCouldNotResolve = 6
	// dnsProbeRetryWindow bounds DNS-failure retries: the synthesized zone lands a beat after management connects, so early NXDOMAIN is propagation; a zone still absent after this window is a real failure.
	dnsProbeRetryWindow   = 30 * time.Second
	dnsProbeRetryInterval = 2 * time.Second
)

// ResolveProxyIP GETs https://<endpoint>/ from the client's netns: any HTTP status proves DNS + tunnel and wakes the lazy proxy peer; only DNS failures retry, within dnsProbeRetryWindow. Returns the connected IP for --resolve pinning.
func (cl *Client) ResolveProxyIP(ctx context.Context, endpoint string) (string, error) {
	args := []string{
		"run", "--rm",
		"--network", "container:" + cl.container.GetContainerID(),
		curlImage,
		"-ksS", "-o", "/dev/null",
		"--connect-timeout", "30", "--max-time", "60",
		"-w", "%{remote_ip}",
		"https://" + endpoint + "/",
	}
	deadline := time.Now().Add(dnsProbeRetryWindow)
	for {
		cmd := exec.CommandContext(ctx, "docker", args...)
		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			ip := strings.TrimSpace(stdout.String())
			if ip == "" {
				return "", fmt.Errorf("got an HTTP response from %s but no remote IP", endpoint)
			}
			return ip, nil
		}

		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != curlExitCouldNotResolve {
			return "", fmt.Errorf("no HTTP response from %s: %w (%s)", endpoint, err, strings.TrimSpace(stderr.String()))
		}
		dnsErr := fmt.Errorf("DNS resolution failed for %s: %s", endpoint, strings.TrimSpace(stderr.String()))
		if time.Until(deadline) < dnsProbeRetryInterval {
			return "", dnsErr
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("%w (%w)", dnsErr, ctx.Err())
		case <-time.After(dnsProbeRetryInterval):
		}
	}
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
	return cl.ChatPrefixed(ctx, endpoint, proxyIP, "", kind, model, prompt, sessionID)
}

// ChatPrefixed is Chat with a base-URL path prefix prepended to the wire
// path, mirroring agents whose base URL carries a shape-selecting prefix that
// rides through to the upstream — e.g. Claude Code against a Kimi provider
// sets ANTHROPIC_BASE_URL=https://<endpoint>/anthropic so the proxy forwards
// /anthropic/v1/messages to Moonshot's Anthropic surface while the provider's
// upstream URL stays the bare https://api.moonshot.ai. Empty prefix is plain
// Chat.
func (cl *Client) ChatPrefixed(ctx context.Context, endpoint, proxyIP, pathPrefix, kind, model, prompt, sessionID string) (int, string, error) {
	var path, body string
	var headers []string
	switch kind {
	case WireMessages:
		path = "/v1/messages"
		headers = []string{"anthropic-version: 2023-06-01"}
		body = fmt.Sprintf(`{"model":%q,"max_tokens":2048,"messages":[{"role":"user","content":%q}]}`, model, prompt)
	default:
		path = "/v1/chat/completions"
		body = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, model, prompt)
	}
	return cl.post(ctx, endpoint, proxyIP, pathPrefix+path, body, withSessionID(headers, sessionID))
}

// ChatStream is Chat with "stream": true in the request body, so the proxy's
// request parser marks the call as streaming and its response parser takes the
// SSE accumulator rather than the buffered-body path. Pair it with a provider
// pointed at VLLM.StreamURL, which answers every request as an event stream.
func (cl *Client) ChatStream(ctx context.Context, endpoint, proxyIP, kind, model, prompt, sessionID string) (int, string, error) {
	var path, body string
	var headers []string
	switch kind {
	case WireMessages:
		path = "/v1/messages"
		headers = []string{"anthropic-version: 2023-06-01"}
		body = fmt.Sprintf(`{"model":%q,"max_tokens":2048,"stream":true,"messages":[{"role":"user","content":%q}]}`, model, prompt)
	default:
		path = "/v1/chat/completions"
		// include_usage is what makes a real OpenAI stream emit its final usage
		// frame; without it the last chunk carries no tokens at all.
		body = fmt.Sprintf(`{"model":%q,"stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":%q}]}`, model, prompt)
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
	body := fmt.Sprintf(`{"anthropic_version":"vertex-2023-10-16","max_tokens":2048,"messages":[{"role":"user","content":%q}]}`, prompt)
	return cl.post(ctx, endpoint, proxyIP, path, body, withSessionID(nil, sessionID))
}

// Bedrock issues a native AWS Bedrock InvokeModel POST over the tunnel. The
// model id is carried in the request path (/model/{id}/invoke), so the proxy
// routes by path; the body uses the bedrock anthropic_version rather than a
// model field. A non-empty sessionID is sent as the universal x-session-id
// header the proxy records.
func (cl *Client) Bedrock(ctx context.Context, endpoint, proxyIP, model, prompt, sessionID string) (int, string, error) {
	path := "/model/" + model + "/invoke"
	body := fmt.Sprintf(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":2048,"messages":[{"role":"user","content":%q}]}`, prompt)
	return cl.post(ctx, endpoint, proxyIP, path, body, withSessionID(nil, sessionID))
}

// withSessionID appends the x-session-id header when sessionID is non-empty.
func withSessionID(headers []string, sessionID string) []string {
	if sessionID == "" {
		return headers
	}
	return append(headers, "x-session-id: "+sessionID)
}

// Get issues a GET to the agent-network endpoint over the client's tunnel.
// Model discovery and the connection-warming probe are read-only endpoints
// that carry no body, so they can't go through the chat helpers.
func (cl *Client) Get(ctx context.Context, endpoint, proxyIP, path string, extraHeaders []string) (int, string, error) {
	return cl.do(ctx, http.MethodGet, endpoint, proxyIP, path, "", extraHeaders)
}

// PostJSON issues an arbitrary JSON POST over the client's tunnel, for wire
// shapes the typed helpers don't cover (token counting, say).
func (cl *Client) PostJSON(ctx context.Context, endpoint, proxyIP, path, body string, extraHeaders []string) (int, string, error) {
	return cl.do(ctx, http.MethodPost, endpoint, proxyIP, path, body, extraHeaders)
}

// post issues a JSON POST. Retained as the shorthand the chat helpers use.
func (cl *Client) post(ctx context.Context, endpoint, proxyIP, path, body string, extraHeaders []string) (int, string, error) {
	return cl.do(ctx, http.MethodPost, endpoint, proxyIP, path, body, extraHeaders)
}

// do runs curl in a throwaway container sharing the client's network
// namespace so the request traverses the WireGuard tunnel, pinning the endpoint
// to the proxy IP. It returns the HTTP status and response body. An empty body
// sends no payload, which is what a GET needs.
func (cl *Client) do(ctx context.Context, method, endpoint, proxyIP, path, body string, extraHeaders []string) (int, string, error) {
	url := "https://" + endpoint + path
	args := []string{
		"run", "--rm",
		"--network", "container:" + cl.container.GetContainerID(),
		curlImage,
		"-sk", "--connect-timeout", "5", "--max-time", "90",
		"--resolve", endpoint + ":443:" + proxyIP,
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

// containerLogs reads up to 4 MiB of a container's logs for diagnostics — enough for a whole provider-matrix run.
func containerLogs(ctx context.Context, c testcontainers.Container) string {
	if c == nil {
		return ""
	}
	r, err := c.Logs(ctx)
	if err != nil {
		return fmt.Sprintf("<logs error: %v>", err)
	}
	defer r.Close()
	b, _ := io.ReadAll(io.LimitReader(r, 4<<20))
	return string(b)
}
