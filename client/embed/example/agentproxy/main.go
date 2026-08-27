// Command agentproxy is a small proof-of-concept that turns a machine into a
// local gateway into a NetBird Agent Network.
//
// It embeds the NetBird client (userspace / netstack mode, so no TUN device
// and no root privileges are required), connects to NetBird the same way a
// regular client does — interactive SSO by default, or a setup key when one
// is supplied via the environment — and then runs a plain HTTP listener on
// localhost:8080. Every request that reaches the listener is reverse-proxied
// over the encrypted NetBird tunnel to an upstream Agent Network endpoint
// (for example https://mirror.netbird.ai).
//
// Because the whole thing runs in userspace and only binds a loopback TCP
// socket, it works on locked-down laptops and in rootless containers
// (OpenShift, Podman, distroless, ...) where a normal netbird agent that
// needs CAP_NET_ADMIN cannot run.
//
// Point an AI agent (Claude Code, Codex, ...) at http://localhost:8080 and
// its traffic flows through the identity-aware Agent Network proxy.
//
// Usage:
//
//	# Interactive SSO login, proxy to the agent network endpoint:
//	agentproxy -upstream https://mirror.netbird.ai
//
//	# Non-interactive with a setup key:
//	NB_SETUP_KEY=xxxxxxxx-... agentproxy -upstream https://mirror.netbird.ai
//
// Environment variables (flags take precedence):
//
//	NB_AGENT_UPSTREAM   upstream agent network URL (e.g. https://mirror.netbird.ai)
//	NB_LISTEN_ADDR      local listen address (default 127.0.0.1:8080)
//	NB_SETUP_KEY        setup key; when set, SSO is skipped
//	NB_MANAGEMENT_URL   management server URL (default https://api.netbird.io:443)
//	NB_DEVICE_NAME      peer name in the network (default agent-proxy)
//	NB_CONFIG_PATH      persist client config here (default: in-memory only)
//	NB_STATE_PATH       persist client state here (optional)
//	NB_HINT             IdP login hint (email) for the SSO screen
//	NB_LOG_LEVEL        embedded client log level (default warn)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	netbird "github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/util"
)

const (
	startTimeout    = 60 * time.Second
	shutdownTimeout = 10 * time.Second
	dialTimeout     = 30 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("agentproxy: %v", err)
	}
}

func run() error {
	var (
		upstreamFlag = flag.String("upstream", "", "upstream agent network URL, e.g. https://mirror.netbird.ai (env NB_AGENT_UPSTREAM)")
		listenFlag   = flag.String("listen", "", "local listen address (default 127.0.0.1:8080, env NB_LISTEN_ADDR)")
		mgmtFlag     = flag.String("management-url", "", "management server URL (env NB_MANAGEMENT_URL)")
		deviceFlag   = flag.String("device-name", "", "peer name in the network (default agent-proxy, env NB_DEVICE_NAME)")
		noBrowser    = flag.Bool("no-browser", false, "do not try to open the SSO URL in a browser")
	)
	flag.Parse()

	upstreamRaw := firstNonEmpty(*upstreamFlag, os.Getenv("NB_AGENT_UPSTREAM"))
	if upstreamRaw == "" {
		return errors.New("upstream agent network URL is required (-upstream or NB_AGENT_UPSTREAM)")
	}
	upstream, err := parseUpstream(upstreamRaw)
	if err != nil {
		return err
	}

	listenAddr := firstNonEmpty(*listenFlag, os.Getenv("NB_LISTEN_ADDR"), "127.0.0.1:8080")
	mgmtURL := firstNonEmpty(*mgmtFlag, os.Getenv("NB_MANAGEMENT_URL"), profilemanager.DefaultManagementURL)
	deviceName := firstNonEmpty(*deviceFlag, os.Getenv("NB_DEVICE_NAME"), "agent-proxy")
	setupKey := os.Getenv("NB_SETUP_KEY")
	logLevel := firstNonEmpty(os.Getenv("NB_LOG_LEVEL"), "warn")

	opts := netbird.Options{
		DeviceName:    deviceName,
		ManagementURL: mgmtURL,
		ConfigPath:    os.Getenv("NB_CONFIG_PATH"),
		StatePath:     os.Getenv("NB_STATE_PATH"),
		LogLevel:      logLevel,
		// The proxy only needs to reach the agent network endpoint; it must
		// never become a stepping stone into the host's LAN and does not
		// accept inbound connections from other peers.
		BlockInbound:   true,
		BlockLANAccess: true,
	}

	switch {
	case setupKey != "":
		log.Printf("authenticating with setup key from NB_SETUP_KEY")
		opts.SetupKey = setupKey
	default:
		log.Printf("no setup key provided, starting interactive SSO login")
		jwt, err := interactiveLogin(context.Background(), mgmtURL, os.Getenv("NB_HINT"), *noBrowser)
		if err != nil {
			return fmt.Errorf("interactive login: %w", err)
		}
		opts.JWTToken = jwt
	}

	client, err := netbird.New(opts)
	if err != nil {
		return fmt.Errorf("create netbird client: %w", err)
	}

	log.Printf("connecting to NetBird (management %s) as %q ...", mgmtURL, deviceName)
	startCtx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	if err := client.Start(startCtx); err != nil {
		return fmt.Errorf("start netbird client: %w", err)
	}
	log.Printf("connected to NetBird network")

	proxy := newAgentProxy(client, upstream)

	server := &http.Server{
		Addr:    listenAddr,
		Handler: proxy,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("listening on http://%s -> %s (over NetBird)", listenAddr, upstream)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return fmt.Errorf("http server: %w", err)
	case sig := <-stop:
		log.Printf("received %s, shutting down ...", sig)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
	if err := client.Stop(shutdownCtx); err != nil {
		log.Printf("netbird shutdown: %v", err)
	}
	return nil
}

// newAgentProxy builds a reverse proxy that forwards every incoming request to
// the upstream agent network endpoint, dialing it over the embedded NetBird
// client so the connection travels inside the encrypted overlay. Hostnames are
// resolved through NetBird's magic DNS by the netstack dialer, so a private
// name such as mirror.netbird.ai reaches the reverse proxy peer directly.
func newAgentProxy(client *netbird.Client, upstream *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// Preserve the standard single-host director but force the outgoing Host
	// header to the upstream host so TLS SNI/verification and the agent
	// network's identity-aware routing see the real endpoint, not
	// localhost:8080.
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = upstream.Host
	}

	// All outbound TCP is dialed through the NetBird tunnel. We build a
	// transport around the embedded client's dialer instead of using
	// client.NewHTTPClient so we keep full control of the reverse-proxy
	// transport knobs.
	proxy.Transport = &http.Transport{
		DialContext:           dialWithTimeout(client.DialContext, dialTimeout),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error for %s %s: %v", r.Method, r.URL.Path, err)
		http.Error(w, "agent network upstream unreachable: "+err.Error(), http.StatusBadGateway)
	}

	return proxy
}

// dialWithTimeout applies a bounded timeout to the connection-establishment
// phase only, leaving the request/response body streaming unbounded.
func dialWithTimeout(dial func(ctx context.Context, network, addr string) (net.Conn, error), d time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return dial(ctx, network, addr)
	}
}

// interactiveLogin drives the standard NetBird OAuth flow (PKCE where a
// desktop session is available, device-code flow otherwise) and returns the
// JWT to hand to the embedded client. This is the same flow the `netbird
// login` CLI uses.
func interactiveLogin(ctx context.Context, mgmtURL, hint string, noBrowser bool) (string, error) {
	config, err := profilemanager.CreateInMemoryConfig(profilemanager.ConfigInput{
		ManagementURL: mgmtURL,
	})
	if err != nil {
		return "", fmt.Errorf("create config: %w", err)
	}

	oauth, err := auth.NewOAuthFlow(ctx, config, util.HasGraphicalSession(), false, hint)
	if err != nil {
		return "", fmt.Errorf("init oauth flow: %w", err)
	}

	flowInfo, err := oauth.RequestAuthInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("request auth info: %w", err)
	}

	uri := flowInfo.VerificationURIComplete
	if uri == "" {
		uri = flowInfo.VerificationURI
	}

	fmt.Fprintln(os.Stderr, "\nPlease complete the SSO login in your browser:")
	fmt.Fprintln(os.Stderr, "\n    "+uri)
	if flowInfo.UserCode != "" && !strings.Contains(uri, flowInfo.UserCode) {
		fmt.Fprintf(os.Stderr, "\n    and enter the code: %s\n", flowInfo.UserCode)
	}
	fmt.Fprintln(os.Stderr)

	if !noBrowser {
		if err := util.OpenBrowser(uri); err != nil {
			log.Printf("could not open browser automatically: %v", err)
		}
	}

	tokenInfo, err := oauth.WaitToken(ctx, flowInfo)
	if err != nil {
		return "", fmt.Errorf("wait for token: %w", err)
	}

	return tokenInfo.GetTokenToUse(), nil
}

func parseUpstream(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("upstream URL %q has no host", raw)
	}
	// Keep only scheme+host; the incoming request path/query is forwarded as-is.
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
