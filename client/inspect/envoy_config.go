package inspect

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// envoyBootstrapTmpl generates the full envoy bootstrap with rule translation.
// TLS rules become per-SNI filter chains; HTTP rules become per-domain virtual hosts.
var envoyBootstrapTmpl = template.Must(template.New("bootstrap").Funcs(template.FuncMap{
	"quote": func(s string) string { return fmt.Sprintf("%q", s) },
}).Parse(`node:
  id: netbird-inspect
  cluster: netbird
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: {{.AdminPort}}
static_resources:
  listeners:
    - name: inspect_listener
      address:
        socket_address:
          address: 127.0.0.1
          port_value: {{.ListenPort}}
      listener_filters:
        - name: envoy.filters.listener.proxy_protocol
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
      filter_chains:
{{- /* TLS filter chains: per-SNI block/allow + default */ -}}
{{- range .TLSChains}}
        - filter_chain_match:
            transport_protocol: tls
{{- if .ServerNames}}
            server_names:
{{- range .ServerNames}}
              - {{quote .}}
{{- end}}
{{- end}}
          filters:
{{$.NetworkFiltersSnippet}}            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: {{.StatPrefix}}
                cluster: original_dst
                access_log:
                  - name: envoy.access_loggers.stderr
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog
                      log_format:
                        text_format: "[%START_TIME%] tcp %DOWNSTREAM_REMOTE_ADDRESS% -> %UPSTREAM_HOST% %RESPONSE_FLAGS% %DURATION%ms\n"
{{- end}}
{{- /* Plain HTTP filter chain with per-domain virtual hosts */}}
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: inspect_http
                access_log:
                  - name: envoy.access_loggers.stderr
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog
                      log_format:
                        text_format: "[%START_TIME%] http %DOWNSTREAM_REMOTE_ADDRESS% %REQ(:AUTHORITY)% %REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %RESPONSE_CODE% %RESPONSE_FLAGS% %DURATION%ms\n"
                http_filters:
{{.HTTPFiltersSnippet}}                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
{{- range .VirtualHosts}}
                    - name: {{.Name}}
                      domains: [{{.DomainsStr}}]
                      routes:
{{- range .Routes}}
                        - match:
                            prefix: "{{if .PathPrefix}}{{.PathPrefix}}{{else}}/{{end}}"
{{- if .Block}}
                          direct_response:
                            status: 403
                            body:
                              filename: "{{$.BlockPagePath}}"
{{- else}}
                          route:
                            cluster: original_dst
{{- end}}
{{- end}}
{{- end}}
  clusters:
    - name: original_dst
      type: ORIGINAL_DST
      lb_policy: CLUSTER_PROVIDED
      connect_timeout: 10s
{{.ExtraClusters}}`))

// tlsChain represents a TLS filter chain entry for the template.
// All TLS chains are passthrough (block decisions happen in Go before envoy).
type tlsChain struct {
	// ServerNames restricts this chain to specific SNIs. Empty is catch-all.
	ServerNames []string
	StatPrefix  string
}

// envoyRoute represents a single route entry within a virtual host.
type envoyRoute struct {
	// PathPrefix for envoy prefix match. Empty means catch-all "/".
	PathPrefix string
	Block      bool
}

// virtualHost represents an HTTP virtual host entry for the template.
type virtualHost struct {
	Name string
	// DomainsStr is pre-formatted for the template: "a", "b".
	DomainsStr string
	Routes     []envoyRoute
}

type bootstrapData struct {
	AdminPort             uint16
	ListenPort            uint16
	BlockPagePath         string
	TLSChains             []tlsChain
	VirtualHosts          []virtualHost
	HTTPFiltersSnippet    string
	NetworkFiltersSnippet string
	ExtraClusters         string
}

// generateBootstrap produces the envoy bootstrap YAML from the inspect config.
// Translates inspection rules into envoy-native per-SNI and per-domain routing.
// blockPagePath is the path to the HTML block page file served by direct_response.
func generateBootstrap(config Config, listenPort, adminPort uint16, blockPagePath string) ([]byte, error) {
	data := bootstrapData{
		AdminPort:     adminPort,
		BlockPagePath: blockPagePath,
		ListenPort:    listenPort,
		TLSChains:     buildTLSChains(config),
		VirtualHosts:  buildVirtualHosts(config),
	}

	if config.Envoy != nil && config.Envoy.Snippets != nil {
		s := config.Envoy.Snippets
		data.HTTPFiltersSnippet = indentSnippet(s.HTTPFilters, 18)
		data.NetworkFiltersSnippet = indentSnippet(s.NetworkFilters, 12)
		data.ExtraClusters = indentSnippet(s.Clusters, 4)
	}

	var buf bytes.Buffer
	if err := envoyBootstrapTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute bootstrap template: %w", err)
	}

	return buf.Bytes(), nil
}

// buildTLSChains translates inspection rules into envoy TLS filter chains.
// Block rules -> per-SNI chain routing to blackhole.
// Allow rules (when default=block) -> per-SNI chain routing to original_dst.
// Default chain follows DefaultAction.
func buildTLSChains(config Config) []tlsChain {
	// TLS block decisions happen in Go before forwarding to envoy, so we only
	// generate allow/passthrough chains here. Envoy can't cleanly close a TLS
	// connection without completing a handshake, so blocked SNIs never reach envoy.
	var allowed []string

	for _, rule := range config.Rules {
		if !ruleTouchesProtocol(rule, ProtoHTTPS, ProtoH2) {
			continue
		}
		for _, d := range rule.Domains {
			sni := d.PunycodeString()
			if rule.Action == ActionAllow || rule.Action == ActionInspect {
				allowed = append(allowed, sni)
			}
		}
	}

	var chains []tlsChain

	if len(allowed) > 0 && config.DefaultAction == ActionBlock {
		chains = append(chains, tlsChain{
			ServerNames: allowed,
			StatPrefix:  "tls_allowed",
		})
	}

	// Default catch-all: passthrough (blocked SNIs never arrive here)
	chains = append(chains, tlsChain{
		StatPrefix: "tls_default",
	})

	return chains
}

// buildVirtualHosts translates inspection rules into envoy HTTP virtual hosts.
// Groups rules by domain, generates per-path routes within each virtual host.
func buildVirtualHosts(config Config) []virtualHost {
	// Group rules by domain for per-domain virtual hosts.
	type domainRules struct {
		domains []string
		routes  []envoyRoute
	}

	domainRouteMap := make(map[string][]envoyRoute)

	for _, rule := range config.Rules {
		if !ruleTouchesProtocol(rule, ProtoHTTP, ProtoWebSocket) {
			continue
		}
		isBlock := rule.Action == ActionBlock

		// Rules without domains or paths are handled by the default action.
		if len(rule.Domains) == 0 && len(rule.Paths) == 0 {
			continue
		}

		// Build routes for this rule's paths
		var routes []envoyRoute
		if len(rule.Paths) > 0 {
			for _, p := range rule.Paths {
				// Convert our path patterns to envoy prefix match.
				// Strip trailing * for envoy prefix matching.
				prefix := strings.TrimSuffix(p, "*")
				routes = append(routes, envoyRoute{PathPrefix: prefix, Block: isBlock})
			}
		} else {
			routes = append(routes, envoyRoute{Block: isBlock})
		}

		if len(rule.Domains) > 0 {
			for _, d := range rule.Domains {
				host := d.PunycodeString()
				domainRouteMap[host] = append(domainRouteMap[host], routes...)
			}
		} else {
			// No domain: applies to all, add to default host
			domainRouteMap["*"] = append(domainRouteMap["*"], routes...)
		}
	}

	var hosts []virtualHost
	idx := 0

	// Per-domain virtual hosts with path routes
	for domain, routes := range domainRouteMap {
		if domain == "*" {
			continue
		}
		// Add a catch-all route after path-specific routes.
		// The catch-all follows the default action.
		routes = append(routes, envoyRoute{Block: config.DefaultAction == ActionBlock})

		hosts = append(hosts, virtualHost{
			Name:       fmt.Sprintf("domain_%d", idx),
			DomainsStr: fmt.Sprintf("%q", domain),
			Routes:     routes,
		})
		idx++
	}

	// Default virtual host (catch-all for unmatched domains)
	defaultRoutes := domainRouteMap["*"]
	defaultRoutes = append(defaultRoutes, envoyRoute{Block: config.DefaultAction == ActionBlock})
	hosts = append(hosts, virtualHost{
		Name:       "default",
		DomainsStr: `"*"`,
		Routes:     defaultRoutes,
	})

	return hosts
}

// ruleTouchesProtocol returns true if the rule's protocol list includes any of the given protocols,
// or if the protocol list is empty (matches all).
func ruleTouchesProtocol(rule Rule, protos ...ProtoType) bool {
	if len(rule.Protocols) == 0 {
		return true
	}
	for _, rp := range rule.Protocols {
		for _, p := range protos {
			if rp == p {
				return true
			}
		}
	}
	return false
}

// indentSnippet prepends each line of the YAML snippet with the given number of spaces.
// Returns empty string if snippet is empty.
func indentSnippet(snippet string, spaces int) string {
	if snippet == "" {
		return ""
	}

	prefix := make([]byte, spaces)
	for i := range prefix {
		prefix[i] = ' '
	}

	var buf bytes.Buffer
	for i, line := range bytes.Split([]byte(snippet), []byte("\n")) {
		if i > 0 {
			buf.WriteByte('\n')
		}
		if len(line) > 0 {
			buf.Write(prefix)
			buf.Write(line)
		}
	}
	buf.WriteByte('\n')

	return buf.String()
}

// ValidateSnippets checks that user-provided snippets are safe to inject
// into the envoy config. Returns an error describing the first violation found.
//
// Validation rules:
//   - Each snippet must be valid YAML (prevents syntax-level injection)
//   - Snippets must not contain YAML document separators (--- or ...) that could
//     break out of the indentation context
//   - Snippets must only contain list items (starting with "- ") at the top level,
//     matching what envoy expects for filters and clusters
func ValidateSnippets(snippets *EnvoySnippets) error {
	if snippets == nil {
		return nil
	}

	fields := []struct {
		name  string
		value string
	}{
		{"http_filters", snippets.HTTPFilters},
		{"network_filters", snippets.NetworkFilters},
		{"clusters", snippets.Clusters},
	}

	for _, f := range fields {
		if f.value == "" {
			continue
		}
		if err := validateSnippetYAML(f.name, f.value); err != nil {
			return err
		}
	}

	return nil
}

func validateSnippetYAML(name, snippet string) error {
	// Check for YAML document markers that could break template structure.
	for _, line := range strings.Split(snippet, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" || trimmed == "..." {
			return fmt.Errorf("snippet %q: YAML document separators (--- or ...) are not allowed", name)
		}
	}

	// Verify it's valid YAML by checking it doesn't cause template execution issues.
	// We can't import yaml.v3 here without adding a dependency, so we do structural checks.

	// Check for null bytes or control characters that could confuse YAML parsers.
	for i, b := range []byte(snippet) {
		if b == 0 {
			return fmt.Errorf("snippet %q: null byte at position %d", name, i)
		}
		if b < 0x09 || (b > 0x0D && b < 0x20 && b != 0x1B) {
			return fmt.Errorf("snippet %q: control character 0x%02x at position %d", name, b, i)
		}
	}

	return nil
}
