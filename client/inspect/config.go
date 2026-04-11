package inspect

import (
	"crypto"
	"crypto/x509"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// InspectResult holds the outcome of connection inspection.
type InspectResult struct {
	// Action is the rule evaluation result.
	Action Action
	// PassthroughConn is the client connection with buffered peeked bytes.
	// Non-nil only when Action is ActionAllow and the caller should relay
	// (TLS passthrough or non-HTTP/TLS protocol). The caller takes ownership
	// and is responsible for closing this connection.
	PassthroughConn net.Conn
}

const (
	// DefaultTProxyPort is the default TPROXY listener port for kernel mode.
	// Override with NB_TPROXY_PORT environment variable.
	DefaultTProxyPort = 22080
)

// Action determines how the proxy handles a matched connection.
type Action string

const (
	// ActionAllow passes the connection through without decryption.
	ActionAllow Action = "allow"
	// ActionBlock denies the connection.
	ActionBlock Action = "block"
	// ActionInspect decrypts (MITM) and inspects the connection.
	ActionInspect Action = "inspect"
)

// ProxyMode determines the proxy operating mode.
type ProxyMode string

const (
	// ModeBuiltin uses the built-in proxy with rules and optional ICAP.
	ModeBuiltin ProxyMode = "builtin"
	// ModeEnvoy runs a local envoy sidecar for L7 processing.
	// Go manages envoy lifecycle, config generation, and rule evaluation.
	// USP path forwards via PROXY protocol v2; kernel path uses nftables redirect.
	ModeEnvoy ProxyMode = "envoy"
	// ModeExternal forwards all traffic to an external proxy.
	ModeExternal ProxyMode = "external"
)

// PolicyID is the management policy identifier associated with a connection.
type PolicyID []byte

// MatchDomain reports whether target matches the pattern.
// If pattern starts with "*.", it matches any subdomain (but not the base itself).
// Otherwise it requires an exact match.
func MatchDomain(pattern, target domain.Domain) bool {
	p := pattern.PunycodeString()
	t := target.PunycodeString()

	if strings.HasPrefix(p, "*.") {
		base := p[2:]
		return strings.HasSuffix(t, "."+base)
	}

	return p == t
}

// SourceInfo carries source identity context for rule evaluation.
// The source may be a direct WireGuard peer or a host behind
// a site-to-site gateway.
type SourceInfo struct {
	// IP is the original source address from the packet.
	IP netip.Addr
	// PolicyID is the management policy that allowed this traffic
	// through route ACLs.
	PolicyID PolicyID
}

// ProtoType identifies a protocol handled by the proxy.
type ProtoType string

const (
	ProtoHTTP      ProtoType = "http"
	ProtoHTTPS     ProtoType = "https"
	ProtoH2        ProtoType = "h2"
	ProtoH3        ProtoType = "h3"
	ProtoWebSocket ProtoType = "websocket"
	ProtoOther     ProtoType = "other"
)

// Rule defines a proxy inspection/filtering rule.
type Rule struct {
	// ID uniquely identifies this rule.
	ID id.RuleID
	// Sources are the source CIDRs this rule applies to.
	// Includes both direct peer IPs and routed networks behind gateways.
	Sources []netip.Prefix
	// Domains are the destination domain patterns to match (via SNI or Host header).
	// Supports exact match ("example.com") and wildcard ("*.example.com").
	Domains []domain.Domain
	// Networks are the destination CIDRs to match.
	Networks []netip.Prefix
	// Ports are the destination ports to match. Empty means all ports.
	Ports []uint16
	// Protocols restricts which protocols this rule applies to.
	// Empty means all protocols.
	Protocols []ProtoType
	// Paths are URL path patterns to match (HTTP only, requires inspect for HTTPS).
	// Supports prefix ("/api/"), exact ("/login"), and wildcard ("/admin/*").
	// Empty means all paths.
	Paths []string
	// Action determines what to do with matched connections.
	Action Action
	// Priority controls evaluation order. Lower values are evaluated first.
	Priority int
}

// ICAPConfig holds ICAP service configuration.
type ICAPConfig struct {
	// ReqModURL is the ICAP REQMOD service URL (e.g., icap://server:1344/reqmod).
	ReqModURL *url.URL
	// RespModURL is the ICAP RESPMOD service URL (e.g., icap://server:1344/respmod).
	RespModURL *url.URL
	// MaxConnections is the connection pool size. Zero uses a default.
	MaxConnections int
}

// TLSConfig holds the MITM CA configuration for TLS inspection.
type TLSConfig struct {
	// CA is the certificate authority used to sign dynamic certificates.
	CA *x509.Certificate
	// CAKey is the CA's private key.
	CAKey crypto.PrivateKey
}

// Config holds the transparent proxy configuration.
type Config struct {
	// Enabled controls whether the proxy is active.
	Enabled bool
	// Mode selects built-in or external proxy operation.
	Mode ProxyMode
	// ExternalURL is the upstream proxy URL for ModeExternal.
	// Supports http:// and socks5:// schemes.
	ExternalURL *url.URL

	// DefaultAction applies when no rule matches a connection.
	DefaultAction Action

	// RedirectSources are the source CIDRs whose traffic should be intercepted.
	// Admin decides: "activate for these users/subnets."
	// Used for both kernel TPROXY rules and userspace forwarder source filtering.
	RedirectSources []netip.Prefix
	// RedirectPorts are the destination ports to intercept. Empty means all ports.
	RedirectPorts []uint16

	// Rules are the proxy inspection/filtering rules, evaluated in Priority order.
	Rules []Rule

	// ICAP holds ICAP service configuration. Nil disables ICAP.
	ICAP *ICAPConfig
	// TLS holds the MITM CA. Nil means no MITM capability (ActionInspect rules ignored).
	TLS *TLSConfig

	// Envoy configuration (ModeEnvoy only)
	Envoy *EnvoyConfig

	// ListenAddr is the TPROXY listen address for kernel mode.
	// Zero value disables the TPROXY listener.
	ListenAddr netip.AddrPort
	// WGNetwork is the WireGuard overlay network prefix.
	// The proxy blocks dialing destinations inside this network.
	WGNetwork netip.Prefix
	// LocalIPChecker reports whether an IP belongs to the routing peer.
	// Used to prevent SSRF to local services. May be nil.
	LocalIPChecker LocalIPChecker
}

// EnvoyConfig holds configuration for the envoy sidecar mode.
type EnvoyConfig struct {
	// BinaryPath is the path to the envoy binary.
	// Empty means search $PATH for "envoy".
	BinaryPath string
	// AdminPort is the port for envoy's admin API (health checks, stats).
	// Zero means auto-assign.
	AdminPort uint16
	// Snippets are user-provided config fragments merged into the generated bootstrap.
	Snippets *EnvoySnippets
}

// EnvoySnippets holds user-provided YAML fragments for envoy config customization.
// Only safe snippet types are allowed: filters (HTTP and network) and clusters
// needed as dependencies for filter services. Listeners and bootstrap overrides
// are not exposed since we manage the listener and bootstrap.
type EnvoySnippets struct {
	// HTTPFilters is YAML injected into the HCM filter chain before the router filter.
	// Used for ext_authz, rate limiting, Lua, Wasm, RBAC, JWT auth, etc.
	HTTPFilters string
	// NetworkFilters is YAML injected into the TLS filter chain before tcp_proxy.
	// Used for network-level RBAC, rate limiting, ext_authz on raw TCP.
	NetworkFilters string
	// Clusters is YAML for additional upstream clusters referenced by filters.
	// Needed when filters call external services (ext_authz backend, rate limit service).
	Clusters string
}
