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
	logLevel := firstNonEmpty(os.Getenv("NB_LOG_LEVEL"), "info")

	// Initialize the shared NetBird logger so the embedded engine's own logs
	// (management/signal/relay handshakes, DNS setup, peer connectivity) are
	// formatted and level-filtered consistently and land on stderr. Set
	// NB_LOG_LEVEL=debug (or trace) to see in-tunnel DNS resolution and per-peer
	// connection detail.
	if err := util.InitLog(logLevel, util.LogConsole); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

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
	logConnected(client)

	// Preflight: resolve and dial the upstream through the tunnel once, up
	// front, so connectivity and in-process DNS resolution are verified (and
	// visible in the logs) before any real request arrives.
	preflight(client, upstream)

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
//
// The returned handler logs every request (method, path, upstream status,
// duration) so it is obvious the proxy is receiving and forwarding traffic.
func newAgentProxy(client *netbird.Client, upstream *url.URL) http.Handler {
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
		DialContext:           loggingDialer(client.DialContext, dialTimeout),
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

	return accessLog(proxy)
}

// accessLog wraps a handler and logs one line per request with the resulting
// upstream status code and total duration.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		log.Printf("-> %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(rec, r)
		log.Printf("<- %s %s %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Truncate(time.Millisecond))
	})
}

// statusRecorder captures the response status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// loggingDialer wraps the embedded client's dialer. It applies a bounded
// timeout to connection establishment (not the full request lifetime) and logs
// each dial — including the tunnel-side local/remote addresses on success —
// which surfaces the in-process DNS resolution and reachability of the target.
func loggingDialer(dial func(ctx context.Context, network, addr string) (net.Conn, error), d time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, d)
		defer cancel()

		start := time.Now()
		conn, err := dial(dialCtx, network, addr)
		if err != nil {
			log.Printf("dial %s %s failed after %s (resolution/connection over tunnel): %v",
				network, addr, time.Since(start).Truncate(time.Millisecond), err)
			return nil, err
		}
		log.Printf("dial %s %s ok in %s (tunnel %s -> %s)",
			network, addr, time.Since(start).Truncate(time.Millisecond),
			conn.LocalAddr(), conn.RemoteAddr())
		return conn, nil
	}
}

// logConnected prints a concise summary of the tunnel state right after the
// client reports up: the local overlay IP/FQDN, control-plane connectivity, and
// how many peers are in the network map.
func logConnected(client *netbird.Client) {
	status, err := client.Status()
	if err != nil {
		log.Printf("connected to NetBird network (status unavailable: %v)", err)
		return
	}
	log.Printf("connected to NetBird network: ip=%s fqdn=%s management=%v signal=%v peers=%d",
		status.LocalPeerState.IP, status.LocalPeerState.FQDN,
		status.ManagementState.Connected, status.SignalState.Connected, len(status.Peers))
}

// preflight resolves and dials the upstream endpoint once over the tunnel so
// any DNS or connectivity problem is reported at startup rather than on the
// first real request. It never fails the process — a proxy that starts but
// cannot yet reach the endpoint is still useful once policy/peers converge.
func preflight(client *netbird.Client, upstream *url.URL) {
	addr := hostPort(upstream)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	log.Printf("preflight: resolving and dialing %s over the tunnel ...", addr)
	conn, err := client.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Printf("preflight: could not reach %s yet: %v", addr, err)
		log.Printf("preflight: this is not fatal; check that %q resolves in your NetBird DNS "+
			"and that a policy grants this peer access to the agent network", upstream.Host)
		return
	}
	log.Printf("preflight: reached %s (tunnel %s -> %s)", addr, conn.LocalAddr(), conn.RemoteAddr())
	_ = conn.Close()
}

// hostPort returns the upstream host with an explicit port, defaulting to the
// scheme's well-known port when the URL omits it.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
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
