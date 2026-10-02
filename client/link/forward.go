// Package link implements nblink, an unprivileged forwarder that exposes local
// listeners and carries their traffic into the NetBird overlay.
//
// The process runs the embedded client in netstack mode, so it needs no TUN
// device and no elevated privileges. Overlay names on the upstream side are
// resolved inside the tunnel rather than through the host resolver.
package link

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// defaultBindHost is used when a forward spec gives a port but no bind address.
// Binding loopback by default keeps the overlay unreachable from the rest of
// the network until the operator opts in.
const defaultBindHost = "127.0.0.1"

// ProtoHTTP forwards HTTP requests to an upstream URL over the overlay.
const ProtoHTTP = "http"

// supportedProtos lists the forward schemes this build accepts. Specs naming a
// known but unimplemented scheme are rejected with a clearer message than an
// unknown one would produce.
var (
	supportedProtos = map[string]bool{ProtoHTTP: true}
	plannedProtos   = map[string]bool{"tcp": true, "udp": true, "socks5": true}

	// schemePrefix matches a URL scheme at the start of a string, per RFC 3986
	// section 3.1.
	schemePrefix = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

	// urlPassword matches the password half of a URL's userinfo. Errors quote
	// the spec the operator typed, which would otherwise echo a password back
	// to the terminal and into whatever captured it.
	urlPassword = regexp.MustCompile(`(//[^/@\s]*):[^/@\s]*@`)
)

// redactSpec replaces any password inside a forward spec, so an error may
// still name the spec it refers to.
func redactSpec(spec string) string {
	return urlPassword.ReplaceAllString(spec, "$1:xxxxx@")
}

// Forward is one local listener and the overlay address it carries traffic to.
type Forward struct {
	// Proto is the listener type, taken from the scheme on the left of the spec.
	Proto string
	// Listen is the local bind address as host:port.
	Listen string
	// Upstream is the target reached over the overlay.
	Upstream *url.URL
	// Spec is the original text, used in logs and errors so the operator sees
	// what they typed rather than a normalized form.
	Spec string
}

// String returns the forward in the spec form the operator wrote.
func (f Forward) String() string {
	return fmt.Sprintf("%s://%s=%s", f.Proto, f.Listen, f.Upstream)
}

// ParseForward parses a forward spec of the form scheme://[host:]port=upstream.
//
// The scheme on the left selects the listener type, the right side is the
// overlay target. A spec that gives only a port binds loopback.
func ParseForward(spec string) (Forward, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Forward{}, fmt.Errorf("empty forward spec")
	}

	schemeEnd := strings.Index(spec, "://")
	if schemeEnd < 0 {
		return Forward{}, fmt.Errorf("forward %q: missing scheme, want scheme://[host:]port=upstream", redactSpec(spec))
	}
	proto := strings.ToLower(spec[:schemeEnd])

	// The left side cannot contain '=', so the first one always separates the
	// listener from the upstream even when the upstream carries a query string.
	sep := strings.Index(spec, "=")
	if sep < 0 || sep < schemeEnd {
		return Forward{}, fmt.Errorf("forward %q: missing '=' between listener and upstream", redactSpec(spec))
	}

	if !supportedProtos[proto] {
		if plannedProtos[proto] {
			return Forward{}, fmt.Errorf("forward %q: %s forwarding is not supported yet, this build handles %s", redactSpec(spec), proto, ProtoHTTP)
		}
		return Forward{}, fmt.Errorf("forward %q: unknown scheme %q", redactSpec(spec), proto)
	}

	listen, err := parseListen(spec[schemeEnd+len("://") : sep])
	if err != nil {
		return Forward{}, fmt.Errorf("forward %q: %w", redactSpec(spec), err)
	}

	upstream, err := parseUpstream(spec[sep+1:])
	if err != nil {
		return Forward{}, fmt.Errorf("forward %q: %w", redactSpec(spec), err)
	}

	return Forward{Proto: proto, Listen: listen, Upstream: upstream, Spec: spec}, nil
}

// parseListen normalizes the listener side of a spec to host:port, defaulting
// the host to loopback when only a port is given.
func parseListen(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("missing listen address")
	}

	host, port := defaultBindHost, raw
	if strings.Contains(raw, ":") {
		h, p, err := net.SplitHostPort(raw)
		if err != nil {
			return "", fmt.Errorf("parse listen address %q: %w", raw, err)
		}
		if h != "" {
			host = h
		}
		port = p
	}

	// Only literal addresses are accepted. A name would be resolved once by
	// the loopback check and again by the bind, and an answer that changed in
	// between would put a listener on a public address without the opt-in. A
	// zone suffix stays allowed: it is part of the literal, resolved the same
	// way at both points, and link-local addresses cannot be bound without it.
	if strings.EqualFold(host, "localhost") {
		host = defaultBindHost
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", fmt.Errorf("listen host %q must be an IP address or localhost", host)
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("listen port %q is not a number", port)
	}
	// Port 0 asks the OS for a free port. The bound address is printed at
	// startup, so the operator still learns where to point a client.
	if n < 0 || n > 65535 {
		return "", fmt.Errorf("listen port %d out of range 0-65535", n)
	}

	return net.JoinHostPort(host, port), nil
}

// parseUpstream validates the overlay target of an HTTP forward. The host is
// resolved later, inside the tunnel, so only the shape is checked here.
func parseUpstream(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("missing upstream")
	}
	// Only a leading scheme counts. A "://" inside a path or query, as in a
	// redirect parameter, belongs to the target rather than to this URL.
	if !schemePrefix.MatchString(raw) {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("upstream scheme %q must be http or https", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("upstream %q has no host", raw)
	}
	// Credentials in the upstream would reach the logs and the --check output,
	// and the forwarder does not use them to authenticate anything.
	if u.User != nil {
		return nil, fmt.Errorf("upstream %q must not carry credentials", u.Redacted())
	}

	return u, nil
}

// isLoopback reports whether addr binds only the loopback interface. The host
// is always a literal address, because parseListen rejects names, so this
// decides the same address the bind will use.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	// Unmap first, so a v4-mapped form such as ::ffff:127.0.0.1 is recognised
	// as the loopback address it is.
	return ip.Unmap().IsLoopback()
}
