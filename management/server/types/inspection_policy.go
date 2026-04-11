package types

import (
	"fmt"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/util/crypt"
)

// InspectionPolicy is a reusable set of L7 inspection rules with proxy configuration.
// Referenced by policies via InspectionPolicies field, similar to posture checks.
// Contains both what to inspect (rules) and how to inspect (CA, ICAP, mode).
type InspectionPolicy struct {
	ID          string `gorm:"primaryKey"`
	AccountID   string `gorm:"index"`
	Name        string
	Description string
	Enabled     bool
	Rules       []InspectionPolicyRule `gorm:"serializer:json"`

	// Mode is the proxy operation mode: "builtin", "envoy", or "external".
	Mode string `json:"mode"`
	// ExternalURL is the upstream proxy URL (HTTP CONNECT or SOCKS5) for external mode.
	ExternalURL string `json:"external_url"`
	// DefaultAction applies when no rule matches: "allow", "block", or "inspect".
	DefaultAction string `json:"default_action"`

	// Redirect ports: which destination ports to intercept at L4.
	// Empty means all ports.
	RedirectPorts []int `gorm:"serializer:json" json:"redirect_ports"`

	// MITM CA certificate and key (PEM-encoded)
	CACertPEM string `json:"ca_cert_pem"`
	CAKeyPEM  string `json:"ca_key_pem"`

	// ICAP configuration for external content scanning
	ICAP *InspectionICAPConfig `gorm:"serializer:json" json:"icap"`

	// Envoy sidecar configuration (mode "envoy" only)
	EnvoyBinaryPath string                   `json:"envoy_binary_path"`
	EnvoyAdminPort  int                      `json:"envoy_admin_port"`
	EnvoySnippets   *InspectionEnvoySnippets `gorm:"serializer:json" json:"envoy_snippets"`
}

// InspectionEnvoySnippets holds user-provided YAML fragments for envoy config customization.
// Only safe snippet types are exposed: filters and clusters. Listeners and bootstrap
// overrides are not allowed since the envoy instance is fully managed.
type InspectionEnvoySnippets struct {
	HTTPFilters    string `json:"http_filters"`
	NetworkFilters string `json:"network_filters"`
	Clusters       string `json:"clusters"`
}

// InspectionICAPConfig holds ICAP protocol settings.
type InspectionICAPConfig struct {
	ReqModURL      string `json:"reqmod_url"`
	RespModURL     string `json:"respmod_url"`
	MaxConnections int    `json:"max_connections"`
}

// InspectionPolicyRule is an L7 rule within an inspection policy.
// No source or network references: sources come from the referencing policy,
// the destination network/routing peer is derived from the policy's destination.
type InspectionPolicyRule struct {
	Domains []string `json:"domains"`
	// Networks restricts this rule to specific destination CIDRs.
	Networks []string `json:"networks"`
	// Protocols this rule applies to: "http", "https", "h2", "h3", "websocket", "other".
	Protocols []string `json:"protocols"`
	// Paths are URL path patterns: "/api/", "/login", "/admin/*".
	Paths    []string `json:"paths"`
	Action   string   `json:"action"`
	Priority int      `json:"priority"`
}

// NewInspectionPolicy creates a new InspectionPolicy with a generated ID.
func NewInspectionPolicy(accountID, name, description string, enabled bool) *InspectionPolicy {
	return &InspectionPolicy{
		ID:          xid.New().String(),
		AccountID:   accountID,
		Name:        name,
		Description: description,
		Enabled:     enabled,
	}
}

// Copy returns a deep copy.
func (p *InspectionPolicy) Copy() *InspectionPolicy {
	c := *p
	c.Rules = make([]InspectionPolicyRule, len(p.Rules))
	for i, r := range p.Rules {
		c.Rules[i] = r
		c.Rules[i].Domains = append([]string{}, r.Domains...)
		c.Rules[i].Networks = append([]string{}, r.Networks...)
		c.Rules[i].Protocols = append([]string{}, r.Protocols...)
	}
	c.RedirectPorts = append([]int{}, p.RedirectPorts...)
	if p.ICAP != nil {
		icap := *p.ICAP
		c.ICAP = &icap
	}
	return &c
}

// EncryptSensitiveData encrypts CA cert and key in place.
func (p *InspectionPolicy) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	var err error
	if p.CACertPEM != "" {
		p.CACertPEM, err = enc.Encrypt(p.CACertPEM)
		if err != nil {
			return fmt.Errorf("encrypt ca_cert_pem: %w", err)
		}
	}
	if p.CAKeyPEM != "" {
		p.CAKeyPEM, err = enc.Encrypt(p.CAKeyPEM)
		if err != nil {
			return fmt.Errorf("encrypt ca_key_pem: %w", err)
		}
	}
	return nil
}

// DecryptSensitiveData decrypts CA cert and key in place.
func (p *InspectionPolicy) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	var err error
	if p.CACertPEM != "" {
		p.CACertPEM, err = enc.Decrypt(p.CACertPEM)
		if err != nil {
			return fmt.Errorf("decrypt ca_cert_pem: %w", err)
		}
	}
	if p.CAKeyPEM != "" {
		p.CAKeyPEM, err = enc.Decrypt(p.CAKeyPEM)
		if err != nil {
			return fmt.Errorf("decrypt ca_key_pem: %w", err)
		}
	}
	return nil
}

// HasDomainOnly returns true if this rule matches by domain and has no CIDR destinations.
func (r *InspectionPolicyRule) HasDomainOnly() bool {
	return len(r.Domains) > 0 && len(r.Networks) == 0
}

// HasCIDRDestination returns true if this rule specifies destination CIDRs.
func (r *InspectionPolicyRule) HasCIDRDestination() bool {
	return len(r.Networks) > 0
}
