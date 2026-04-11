package types

import (
	proto "github.com/netbirdio/netbird/shared/management/proto"
)

// TransparentProxyAction determines the proxy behavior for matched connections.
type TransparentProxyAction int

const (
	TransparentProxyActionAllow   TransparentProxyAction = 0
	TransparentProxyActionBlock   TransparentProxyAction = 1
	TransparentProxyActionInspect TransparentProxyAction = 2
)

// TransparentProxyMode selects built-in or external proxy operation.
type TransparentProxyMode int

const (
	TransparentProxyModeBuiltin  TransparentProxyMode = 0
	TransparentProxyModeExternal TransparentProxyMode = 1
	TransparentProxyModeEnvoy    TransparentProxyMode = 2
)

// TransparentProxyConfig holds the transparent proxy configuration for a routing peer.
type TransparentProxyConfig struct {
	Enabled       bool
	Mode          TransparentProxyMode
	ExternalURL   string
	DefaultAction TransparentProxyAction
	// RedirectSources is the set of source CIDRs to intercept.
	RedirectSources []string
	RedirectPorts   []uint16
	Rules           []TransparentProxyRule
	ICAP            *TransparentProxyICAPConfig
	CACertPEM       []byte
	CAKeyPEM        []byte
	ListenPort      uint16

	// Envoy sidecar fields (ModeEnvoy only)
	EnvoyBinaryPath string
	EnvoyAdminPort  uint16
	EnvoySnippets   *TransparentProxyEnvoySnippets
}

// TransparentProxyEnvoySnippets holds user-provided YAML fragments for envoy config.
type TransparentProxyEnvoySnippets struct {
	HTTPFilters    string
	NetworkFilters string
	Clusters       string
}

// TransparentProxyRule is an L7 inspection rule evaluated by the proxy engine.
type TransparentProxyRule struct {
	ID string
	// Domains are domain patterns, e.g. "*.example.com".
	Domains []string
	// Networks restricts this rule to specific destination CIDRs.
	Networks []string
	// Protocols this rule applies to: "http", "https", "h2", "h3", "websocket", "other".
	Protocols []string
	// Paths are URL path patterns: "/api/", "/login", "/admin/*".
	Paths    []string
	Action   TransparentProxyAction
	Priority int
}

// TransparentProxyICAPConfig holds ICAP service configuration.
type TransparentProxyICAPConfig struct {
	ReqModURL      string
	RespModURL     string
	MaxConnections int
}

// ToProto converts the internal config to the proto representation.
func (c *TransparentProxyConfig) ToProto() *proto.TransparentProxyConfig {
	if c == nil {
		return nil
	}

	pc := &proto.TransparentProxyConfig{
		Enabled:       c.Enabled,
		Mode:          proto.TransparentProxyMode(c.Mode),
		DefaultAction: proto.TransparentProxyAction(c.DefaultAction),
		CaCertPem:     c.CACertPEM,
		CaKeyPem:      c.CAKeyPEM,
		ListenPort:    uint32(c.ListenPort),
	}

	if c.ExternalURL != "" {
		pc.ExternalProxyUrl = c.ExternalURL
	}

	if c.Mode == TransparentProxyModeEnvoy {
		pc.EnvoyBinaryPath = c.EnvoyBinaryPath
		pc.EnvoyAdminPort = uint32(c.EnvoyAdminPort)
		if c.EnvoySnippets != nil {
			pc.EnvoySnippets = &proto.TransparentProxyEnvoySnippets{
				HttpFilters:    c.EnvoySnippets.HTTPFilters,
				NetworkFilters: c.EnvoySnippets.NetworkFilters,
				Clusters:       c.EnvoySnippets.Clusters,
			}
		}
	}

	pc.RedirectSources = c.RedirectSources

	redirectPorts := make([]uint32, len(c.RedirectPorts))
	for i, p := range c.RedirectPorts {
		redirectPorts[i] = uint32(p)
	}
	pc.RedirectPorts = redirectPorts

	for _, r := range c.Rules {
		pr := &proto.TransparentProxyRule{
			Id:       r.ID,
			Domains:  r.Domains,
			Networks: r.Networks,
			Paths:    r.Paths,
			Action:   proto.TransparentProxyAction(r.Action),
			Priority: int32(r.Priority),
		}
		for _, p := range r.Protocols {
			pr.Protocols = append(pr.Protocols, stringToProtoProtocol(p))
		}
		pc.Rules = append(pc.Rules, pr)
	}

	if c.ICAP != nil {
		pc.Icap = &proto.TransparentProxyICAPConfig{
			ReqmodUrl:      c.ICAP.ReqModURL,
			RespmodUrl:     c.ICAP.RespModURL,
			MaxConnections: int32(c.ICAP.MaxConnections),
		}
	}

	return pc
}

// stringToProtoProtocol maps a protocol string to its proto enum value.
func stringToProtoProtocol(s string) proto.TransparentProxyProtocol {
	switch s {
	case "http":
		return proto.TransparentProxyProtocol_TP_PROTO_HTTP
	case "https":
		return proto.TransparentProxyProtocol_TP_PROTO_HTTPS
	case "h2":
		return proto.TransparentProxyProtocol_TP_PROTO_H2
	case "h3":
		return proto.TransparentProxyProtocol_TP_PROTO_H3
	case "websocket":
		return proto.TransparentProxyProtocol_TP_PROTO_WEBSOCKET
	case "other":
		return proto.TransparentProxyProtocol_TP_PROTO_OTHER
	default:
		return proto.TransparentProxyProtocol_TP_PROTO_ALL
	}
}
