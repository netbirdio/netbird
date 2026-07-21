package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/shared/hash/argon2id"
	nbdomain "github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/util/crypt"

	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type Operation string

const (
	Create Operation = "create"
	Update Operation = "update"
	Delete Operation = "delete"
)

type Status string
type TargetType string

const (
	StatusPending            Status = "pending"
	StatusActive             Status = "active"
	StatusTunnelNotCreated   Status = "tunnel_not_created"
	StatusCertificatePending Status = "certificate_pending"
	StatusCertificateFailed  Status = "certificate_failed"
	StatusError              Status = "error"

	TargetTypePeer    TargetType = "peer"
	TargetTypeHost    TargetType = "host"
	TargetTypeDomain  TargetType = "domain"
	TargetTypeSubnet  TargetType = "subnet"
	TargetTypeCluster TargetType = "cluster"

	SourcePermanent = "permanent"
	SourceEphemeral = "ephemeral"
)

type TargetOptions struct {
	SkipTLSVerify      bool              `json:"skip_tls_verify"`
	RequestTimeout     time.Duration     `json:"request_timeout,omitempty"`
	SessionIdleTimeout time.Duration     `json:"session_idle_timeout,omitempty"`
	PathRewrite        PathRewriteMode   `json:"path_rewrite,omitempty"`
	CustomHeaders      map[string]string `gorm:"serializer:json" json:"custom_headers,omitempty"`
	// DirectUpstream bypasses the proxy's embedded NetBird client and dials
	// the target via the proxy host's network stack. Useful for upstreams
	// reachable without WireGuard (public APIs, LAN services, localhost
	// sidecars). Default false.
	DirectUpstream bool `json:"direct_upstream,omitempty"`
	// Middlewares carries per-target agent-network middleware configs. Empty
	// for private and operator-defined services; populated only by the
	// agent-network synthesizer.
	Middlewares             []MiddlewareConfig `gorm:"serializer:json" json:"middlewares,omitempty"`
	CaptureMaxRequestBytes  int64              `json:"capture_max_request_bytes,omitempty"`
	CaptureMaxResponseBytes int64              `json:"capture_max_response_bytes,omitempty"`
	CaptureContentTypes     []string           `gorm:"serializer:json" json:"capture_content_types,omitempty"`
	// AgentNetwork marks targets synthesised from Agent Network state. The
	// proxy uses it to gate agent-network-specific behaviour (access log
	// tagging, observability, etc.).
	AgentNetwork bool `json:"agent_network,omitempty"`
	// DisableAccessLog suppresses the per-request access-log emission for this
	// target. Defaults false to preserve access-log behaviour for every
	// non-agent-network target. The agent-network synthesizer sets this true
	// only when the account's EnableLogCollection toggle is off.
	DisableAccessLog bool `json:"disable_access_log,omitempty"`
}

// MiddlewareSlot mirrors proto.MiddlewareSlot / middleware.Slot.
type MiddlewareSlot string

const (
	MiddlewareSlotOnRequest  MiddlewareSlot = "on_request"
	MiddlewareSlotOnResponse MiddlewareSlot = "on_response"
	MiddlewareSlotTerminal   MiddlewareSlot = "terminal"
)

// MiddlewareFailMode mirrors proto.MiddlewareConfig_FailMode.
type MiddlewareFailMode string

const (
	MiddlewareFailOpen   MiddlewareFailMode = "fail_open"
	MiddlewareFailClosed MiddlewareFailMode = "fail_closed"
)

// MiddlewareConfig is the per-target configuration for a single
// middleware instance. Mirrors proto.MiddlewareConfig.
type MiddlewareConfig struct {
	ID         string             `json:"id"`
	Enabled    bool               `json:"enabled"`
	Slot       MiddlewareSlot     `json:"slot"`
	ConfigJSON []byte             `json:"config_json,omitempty"`
	FailMode   MiddlewareFailMode `json:"fail_mode,omitempty"`
	TimeoutMs  int32              `json:"timeout_ms,omitempty"`
	CanMutate  bool               `json:"can_mutate"`
}

type Target struct {
	ID            uint          `gorm:"primaryKey" json:"-"`
	AccountID     string        `gorm:"index:idx_target_account;not null" json:"-"`
	ServiceID     string        `gorm:"index:idx_service_targets;not null" json:"-"`
	Path          *string       `json:"path,omitempty"`
	Host          string        `json:"host"`
	Port          uint16        `gorm:"index:idx_target_port" json:"port"`
	Protocol      string        `gorm:"index:idx_target_protocol" json:"protocol"`
	TargetId      string        `gorm:"index:idx_target_id" json:"target_id"`
	TargetType    TargetType    `gorm:"index:idx_target_type" json:"target_type"`
	Enabled       bool          `gorm:"index:idx_target_enabled" json:"enabled"`
	Options       TargetOptions `gorm:"embedded" json:"options"`
	ProxyProtocol bool          `json:"proxy_protocol"`
}

// PortMapping describes an inclusive public listener range translated
// one-to-one onto an equally sized target range. Position preserves the API
// array order without making row IDs part of the public contract.
type PortMapping struct {
	ID              uint   `gorm:"primaryKey" json:"-"`
	AccountID       string `gorm:"index:idx_service_port_mapping_account;not null" json:"-"`
	ServiceID       string `gorm:"index:idx_service_port_mappings;not null" json:"-"`
	Protocol        string `gorm:"type:varchar(8);index:idx_service_port_mapping_listener,priority:1;not null" json:"protocol"`
	ListenPortStart uint16 `gorm:"index:idx_service_port_mapping_listener,priority:2;not null" json:"listen_port_start"`
	ListenPortEnd   uint16 `gorm:"not null" json:"listen_port_end"`
	TargetPortStart uint16 `gorm:"not null" json:"target_port_start"`
	TargetPortEnd   uint16 `gorm:"not null" json:"target_port_end"`
	Position        int    `gorm:"not null;default:0" json:"-"`
}

// TableName keeps the association name explicit and avoids colliding with
// unrelated port-mapping concepts.
func (PortMapping) TableName() string {
	return "service_port_mappings"
}

type PasswordAuthConfig struct {
	Enabled  bool   `json:"enabled"`
	Password string `json:"password"`
}

type PINAuthConfig struct {
	Enabled bool   `json:"enabled"`
	Pin     string `json:"pin"`
}

type BearerAuthConfig struct {
	Enabled            bool     `json:"enabled"`
	DistributionGroups []string `json:"distribution_groups,omitempty" gorm:"serializer:json"`
}

// HeaderAuthConfig defines a static header-value auth check.
// The proxy compares the incoming header value against the stored hash.
type HeaderAuthConfig struct {
	Enabled bool   `json:"enabled"`
	Header  string `json:"header"`
	Value   string `json:"value"`
}

type AuthConfig struct {
	PasswordAuth *PasswordAuthConfig `json:"password_auth,omitempty" gorm:"serializer:json"`
	PinAuth      *PINAuthConfig      `json:"pin_auth,omitempty" gorm:"serializer:json"`
	BearerAuth   *BearerAuthConfig   `json:"bearer_auth,omitempty" gorm:"serializer:json"`
	HeaderAuths  []*HeaderAuthConfig `json:"header_auths,omitempty" gorm:"serializer:json"`
}

// AccessRestrictions controls who can connect to the service based on IP or geography.
type AccessRestrictions struct {
	AllowedCIDRs     []string `json:"allowed_cidrs,omitempty" gorm:"serializer:json"`
	BlockedCIDRs     []string `json:"blocked_cidrs,omitempty" gorm:"serializer:json"`
	AllowedCountries []string `json:"allowed_countries,omitempty" gorm:"serializer:json"`
	BlockedCountries []string `json:"blocked_countries,omitempty" gorm:"serializer:json"`
	CrowdSecMode     string   `json:"crowdsec_mode,omitempty" gorm:"serializer:json"`
}

// Copy returns a deep copy of the AccessRestrictions.
func (r AccessRestrictions) Copy() AccessRestrictions {
	return AccessRestrictions{
		AllowedCIDRs:     slices.Clone(r.AllowedCIDRs),
		BlockedCIDRs:     slices.Clone(r.BlockedCIDRs),
		AllowedCountries: slices.Clone(r.AllowedCountries),
		BlockedCountries: slices.Clone(r.BlockedCountries),
		CrowdSecMode:     r.CrowdSecMode,
	}
}

func (a *AuthConfig) HashSecrets() error {
	if a.PasswordAuth != nil && a.PasswordAuth.Enabled && a.PasswordAuth.Password != "" {
		hashedPassword, err := argon2id.Hash(a.PasswordAuth.Password)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		a.PasswordAuth.Password = hashedPassword
	}

	if a.PinAuth != nil && a.PinAuth.Enabled && a.PinAuth.Pin != "" {
		hashedPin, err := argon2id.Hash(a.PinAuth.Pin)
		if err != nil {
			return fmt.Errorf("hash pin: %w", err)
		}
		a.PinAuth.Pin = hashedPin
	}

	for i, h := range a.HeaderAuths {
		if h != nil && h.Enabled && h.Value != "" {
			hashedValue, err := argon2id.Hash(h.Value)
			if err != nil {
				return fmt.Errorf("hash header auth[%d] value: %w", i, err)
			}
			h.Value = hashedValue
		}
	}

	return nil
}

func (a *AuthConfig) ClearSecrets() {
	if a.PasswordAuth != nil {
		a.PasswordAuth.Password = ""
	}
	if a.PinAuth != nil {
		a.PinAuth.Pin = ""
	}
	for _, h := range a.HeaderAuths {
		if h != nil {
			h.Value = ""
		}
	}
}

type Meta struct {
	CreatedAt           time.Time
	CertificateIssuedAt *time.Time
	Status              string
	LastRenewedAt       *time.Time
}

type Service struct {
	ID                string `gorm:"primaryKey"`
	AccountID         string `gorm:"index"`
	Name              string
	Domain            string         `gorm:"type:varchar(255);index:idx_services_domain_lookup"`
	HTTPDomain        *string        `gorm:"type:varchar(255);uniqueIndex:idx_services_http_domain" json:"-"`
	ProxyCluster      string         `gorm:"index"`
	Targets           []*Target      `gorm:"foreignKey:ServiceID;constraint:OnDelete:CASCADE"`
	PortMappings      []*PortMapping `gorm:"foreignKey:ServiceID;constraint:OnDelete:CASCADE"`
	Enabled           bool
	Terminated        bool
	PassHostHeader    bool
	RewriteRedirects  bool
	Auth              AuthConfig         `gorm:"serializer:json"`
	Restrictions      AccessRestrictions `gorm:"serializer:json"`
	Meta              Meta               `gorm:"embedded;embeddedPrefix:meta_"`
	SessionPrivateKey string             `gorm:"column:session_private_key"`
	SessionPublicKey  string             `gorm:"column:session_public_key"`
	Source            string             `gorm:"default:'permanent';index:idx_service_source_peer"`
	SourcePeer        string             `gorm:"index:idx_service_source_peer"`
	// Mode determines the service type: "http", "tcp", "udp", or "tls".
	Mode             string `gorm:"default:'http'"`
	ListenPort       uint16
	PortAutoAssigned bool
	// Private marks the service as NetBird-only: auth via ValidateTunnelPeer against AccessGroups instead of SSO. HTTP-only.
	Private bool
	// AccessGroups is the group ID allowlist for inbound peers on private services. Mutually exclusive with bearer SSO.
	AccessGroups []string `json:"access_groups,omitempty" gorm:"serializer:json"`
	// PortMappingsSet records whether an API request explicitly supplied the
	// new collection. It is transient and protects multi-port services from
	// accidental collapse by legacy update clients.
	PortMappingsSet bool `gorm:"-" json:"-"`
}

// DomainLock is a durable serialization key for reverse-proxy hostname
// ownership checks. The row is intentionally retained after services are
// deleted: keeping a small, append-only set of canonical hostnames lets an
// absent service set be locked portably on PostgreSQL, MySQL, and SQLite.
//
// It contains no tenant data because reverse-proxy hostnames are globally
// routed and therefore must be serialized across accounts.
type DomainLock struct {
	Domain string `gorm:"type:varchar(255);primaryKey"`
}

func (DomainLock) TableName() string {
	return "reverse_proxy_domain_locks"
}

// InitNewRecord generates a new unique ID and resets metadata for a newly created
// Service record. This overwrites any existing ID and Meta fields and should
// only be called during initial creation, not for updates.
func (s *Service) InitNewRecord() {
	s.ID = xid.New().String()
	s.Meta = Meta{
		CreatedAt: time.Now(),
		Status:    string(StatusPending),
	}
	s.preparePortMappings()
}

// IsL4 reports whether the service uses the layer-4 model. PortMappings is
// checked as well as Mode so partially constructed API requests are handled
// correctly before their legacy mirror fields are synchronized.
func (s *Service) IsL4() bool {
	return len(s.PortMappings) > 0 || IsL4Protocol(s.Mode)
}

// CanonicalDomain converts a hostname to the lower-case, IDNA ASCII form used
// for persistence and routing lookups. A single trailing root label is ignored
// so equivalent FQDN spellings share the same ownership key.
func CanonicalDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", nil
	}

	d, err := nbdomain.FromString(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize domain %q: %w", value, err)
	}
	return d.PunycodeString(), nil
}

// CanonicalizeDomain normalizes Domain and refreshes the nullable ownership
// key that enforces one HTTP service per hostname at the database layer. L4
// services intentionally leave HTTPDomain nil so they can share a hostname.
func (s *Service) CanonicalizeDomain() error {
	canonical, err := CanonicalDomain(s.Domain)
	if err != nil {
		return err
	}
	s.Domain = canonical
	s.refreshHTTPDomain()
	return nil
}

func (s *Service) refreshHTTPDomain() {
	if s.Domain == "" || s.IsL4() {
		s.HTTPDomain = nil
		return
	}
	value := s.Domain
	s.HTTPDomain = &value
}

// PopulatePortMappingsFromLegacy converts a complete scalar L4
// representation into a one-element collection. It deliberately leaves a
// legacy auto-assigned listener at zero alone; the manager calls it after
// choosing the port.
func (s *Service) PopulatePortMappingsFromLegacy() {
	if len(s.PortMappings) > 0 || !IsL4Protocol(s.Mode) || s.ListenPort == 0 || len(s.Targets) != 1 || s.Targets[0].Port == 0 {
		return
	}

	s.PortMappings = []*PortMapping{{
		AccountID:       s.AccountID,
		ServiceID:       s.ID,
		Protocol:        s.Mode,
		ListenPortStart: s.ListenPort,
		ListenPortEnd:   s.ListenPort,
		TargetPortStart: s.Targets[0].Port,
		TargetPortEnd:   s.Targets[0].Port,
	}}
	s.preparePortMappings()
}

// syncLegacyFields mirrors the first mapping into the original scalar fields.
// Those fields remain populated so older clients and proxies retain the
// existing single-port view. PortMappings is authoritative when present.
func (s *Service) syncLegacyFields() {
	if len(s.PortMappings) == 0 || len(s.Targets) == 0 {
		return
	}

	first := s.PortMappings[0]
	s.Mode = first.Protocol
	s.ListenPort = first.ListenPortStart
	s.PortAutoAssigned = false
	s.Targets[0].Port = first.TargetPortStart
	s.Targets[0].Protocol = targetProtocolForMapping(first.Protocol)
	s.preparePortMappings()
}

func (s *Service) preparePortMappings() {
	for i, mapping := range s.PortMappings {
		if mapping == nil {
			continue
		}
		mapping.AccountID = s.AccountID
		mapping.ServiceID = s.ID
		mapping.Position = i
	}
}

func targetProtocolForMapping(protocol string) string {
	if protocol == ModeUDP {
		return TargetProtoUDP
	}
	return TargetProtoTCP
}

// RequiresMultiPortCapability reports whether the service cannot be faithfully
// represented by the legacy scalar fields and first target port.
func (s *Service) RequiresMultiPortCapability() bool {
	if len(s.PortMappings) == 0 {
		return false
	}
	if len(s.PortMappings) != 1 {
		return true
	}
	mapping := s.PortMappings[0]
	if mapping == nil || len(s.Targets) != 1 {
		return true
	}
	return mapping.ListenPortStart != mapping.ListenPortEnd ||
		mapping.TargetPortStart != mapping.TargetPortEnd ||
		mapping.Protocol != s.Mode ||
		mapping.ListenPortStart != s.ListenPort ||
		mapping.TargetPortStart != s.Targets[0].Port
}

func (s *Service) ToAPIResponse() *api.Service {
	mode := api.ServiceMode(s.Mode)
	listenPort := int(s.ListenPort)
	resp := &api.Service{
		Id:                 s.ID,
		Name:               s.Name,
		Domain:             s.Domain,
		Targets:            serviceTargetsToAPI(s.Targets, s.Terminated),
		Enabled:            s.Enabled && !s.Terminated,
		Terminated:         &s.Terminated,
		PassHostHeader:     &s.PassHostHeader,
		RewriteRedirects:   &s.RewriteRedirects,
		Auth:               serviceAuthToAPI(s.Auth),
		AccessRestrictions: restrictionsToAPI(s.Restrictions),
		Meta:               serviceMetaToAPI(s.Meta),
		Mode:               &mode,
		ListenPort:         &listenPort,
		PortAutoAssigned:   &s.PortAutoAssigned,
		PortMappings:       servicePortMappingsToAPI(s),
		Private:            &s.Private,
	}

	if len(s.AccessGroups) > 0 {
		groups := append([]string(nil), s.AccessGroups...)
		resp.AccessGroups = &groups
	}

	if s.ProxyCluster != "" {
		resp.ProxyCluster = &s.ProxyCluster
	}

	return resp
}

// ToProtoMapping converts the service into the wire format the proxy consumes.
func (s *Service) ToProtoMapping(operation Operation, authToken string, oidcConfig proxy.OIDCValidationConfig) *proto.ProxyMapping {
	pathMappings := s.buildPathMappings()

	auth := &proto.Authentication{
		SessionKey:           s.SessionPublicKey,
		MaxSessionAgeSeconds: int64((time.Hour * 24).Seconds()),
	}

	if s.Auth.PasswordAuth != nil && s.Auth.PasswordAuth.Enabled {
		auth.Password = true
	}

	if s.Auth.PinAuth != nil && s.Auth.PinAuth.Enabled {
		auth.Pin = true
	}

	if s.Auth.BearerAuth != nil && s.Auth.BearerAuth.Enabled {
		auth.Oidc = true
	}

	for _, h := range s.Auth.HeaderAuths {
		if h != nil && h.Enabled {
			auth.HeaderAuths = append(auth.HeaderAuths, &proto.HeaderAuth{
				Header:      h.Header,
				HashedValue: h.Value,
			})
		}
	}

	mapping := &proto.ProxyMapping{
		Type:             operationToProtoType(operation),
		Id:               s.ID,
		Domain:           s.Domain,
		Path:             pathMappings,
		AuthToken:        authToken,
		Auth:             auth,
		AccountId:        s.AccountID,
		PassHostHeader:   s.PassHostHeader,
		RewriteRedirects: s.RewriteRedirects,
		Mode:             s.Mode,
		ListenPort:       int32(s.ListenPort), //nolint:gosec
		Private:          s.Private,
	}
	if s.RequiresMultiPortCapability() {
		mapping.PortMappings = make([]*proto.ServicePortMapping, 0, len(s.PortMappings))
		for _, portMapping := range s.PortMappings {
			if portMapping == nil {
				continue
			}
			mapping.PortMappings = append(mapping.PortMappings, &proto.ServicePortMapping{
				Protocol:        portMapping.Protocol,
				ListenPortStart: uint32(portMapping.ListenPortStart),
				ListenPortEnd:   uint32(portMapping.ListenPortEnd),
				TargetPortStart: uint32(portMapping.TargetPortStart),
				TargetPortEnd:   uint32(portMapping.TargetPortEnd),
			})
		}
	}

	if r := restrictionsToProto(s.Restrictions); r != nil {
		mapping.AccessRestrictions = r
	}

	return mapping
}

// buildPathMappings constructs PathMapping entries from targets.
// For HTTP/HTTPS, each target becomes a path-based route with a full URL.
// For L4/TLS, a single target maps to a host:port address.
func (s *Service) buildPathMappings() []*proto.PathMapping {
	pathMappings := make([]*proto.PathMapping, 0, len(s.Targets))
	for _, target := range s.Targets {
		if !target.Enabled {
			continue
		}

		if IsL4Protocol(s.Mode) {
			pm := &proto.PathMapping{
				Target: net.JoinHostPort(target.Host, strconv.FormatUint(uint64(target.Port), 10)),
			}
			opts := l4TargetOptionsToProto(target)
			if opts != nil {
				pm.Options = opts
			}
			pathMappings = append(pathMappings, pm)
			continue
		}

		// HTTP/HTTPS: build full URL
		hostNoBrackets := strings.TrimSuffix(strings.TrimPrefix(target.Host, "["), "]")
		targetURL := url.URL{
			Scheme: target.Protocol,
			Host:   bracketIPv6Host(hostNoBrackets),
			Path:   "/",
		}
		if target.Port > 0 && !isDefaultPort(target.Protocol, target.Port) {
			targetURL.Host = net.JoinHostPort(hostNoBrackets, strconv.FormatUint(uint64(target.Port), 10))
		}

		path := "/"
		if target.Path != nil {
			path = *target.Path
		}

		pm := &proto.PathMapping{
			Path:   path,
			Target: targetURL.String(),
		}
		pm.Options = targetOptionsToProto(target.Options)
		pathMappings = append(pathMappings, pm)
	}
	return pathMappings
}

// bracketIPv6Host wraps host in square brackets when it is an IPv6 literal, as
// required for the Host field of net/url.URL (RFC 3986 §3.2.2). v4-mapped IPv6
// addresses are bracketed too since their textual form contains colons.
func bracketIPv6Host(host string) string {
	if strings.HasPrefix(host, "[") {
		return host
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return "[" + host + "]"
	}
	return host
}

func operationToProtoType(op Operation) proto.ProxyMappingUpdateType {
	switch op {
	case Create:
		return proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED
	case Update:
		return proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED
	case Delete:
		return proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED
	default:
		panic(fmt.Sprintf("unknown operation type: %v", op))
	}
}

// isDefaultPort reports whether port is the standard default for the given scheme
// (443 for https, 80 for http).
func isDefaultPort(scheme string, port uint16) bool {
	return (scheme == TargetProtoHTTPS && port == 443) || (scheme == TargetProtoHTTP && port == 80)
}

// PathRewriteMode controls how the request path is rewritten before forwarding.
type PathRewriteMode string

const (
	PathRewritePreserve PathRewriteMode = "preserve"
)

func pathRewriteToProto(mode PathRewriteMode) proto.PathRewriteMode {
	switch mode {
	case PathRewritePreserve:
		return proto.PathRewriteMode_PATH_REWRITE_PRESERVE
	default:
		return proto.PathRewriteMode_PATH_REWRITE_DEFAULT
	}
}

func targetOptionsToProto(opts TargetOptions) *proto.PathTargetOptions {
	if !opts.SkipTLSVerify && opts.PathRewrite == "" && opts.RequestTimeout == 0 &&
		len(opts.CustomHeaders) == 0 && !opts.DirectUpstream &&
		len(opts.Middlewares) == 0 && opts.CaptureMaxRequestBytes == 0 &&
		opts.CaptureMaxResponseBytes == 0 && len(opts.CaptureContentTypes) == 0 &&
		!opts.AgentNetwork && !opts.DisableAccessLog {
		return nil
	}
	popts := &proto.PathTargetOptions{
		SkipTlsVerify:    opts.SkipTLSVerify,
		PathRewrite:      pathRewriteToProto(opts.PathRewrite),
		CustomHeaders:    opts.CustomHeaders,
		DirectUpstream:   opts.DirectUpstream,
		AgentNetwork:     opts.AgentNetwork,
		DisableAccessLog: opts.DisableAccessLog,
	}
	if opts.RequestTimeout != 0 {
		popts.RequestTimeout = durationpb.New(opts.RequestTimeout)
	}
	if len(opts.Middlewares) > 0 {
		popts.Middlewares = middlewaresToProto(opts.Middlewares)
	}
	popts.CaptureMaxRequestBytes = opts.CaptureMaxRequestBytes
	popts.CaptureMaxResponseBytes = opts.CaptureMaxResponseBytes
	if len(opts.CaptureContentTypes) > 0 {
		popts.CaptureContentTypes = append([]string(nil), opts.CaptureContentTypes...)
	}
	return popts
}

// middlewaresToProto converts the internal middleware slice to the proto
// representation sent to the proxy via the mapping stream.
func middlewaresToProto(in []MiddlewareConfig) []*proto.MiddlewareConfig {
	out := make([]*proto.MiddlewareConfig, 0, len(in))
	for _, m := range in {
		pm := &proto.MiddlewareConfig{
			Id:         m.ID,
			Enabled:    m.Enabled,
			Slot:       middlewareSlotToProto(m.Slot),
			ConfigJson: append([]byte(nil), m.ConfigJSON...),
			CanMutate:  m.CanMutate,
			FailMode:   middlewareFailModeToProto(m.FailMode),
		}
		if m.TimeoutMs > 0 {
			pm.Timeout = durationpb.New(time.Duration(m.TimeoutMs) * time.Millisecond)
		}
		out = append(out, pm)
	}
	return out
}

func middlewareSlotToProto(s MiddlewareSlot) proto.MiddlewareSlot {
	switch s {
	case MiddlewareSlotOnRequest:
		return proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST
	case MiddlewareSlotOnResponse:
		return proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE
	case MiddlewareSlotTerminal:
		return proto.MiddlewareSlot_MIDDLEWARE_SLOT_TERMINAL
	default:
		return proto.MiddlewareSlot_MIDDLEWARE_SLOT_UNSPECIFIED
	}
}

func middlewareFailModeToProto(m MiddlewareFailMode) proto.MiddlewareConfig_FailMode {
	if m == MiddlewareFailClosed {
		return proto.MiddlewareConfig_FAIL_CLOSED
	}
	return proto.MiddlewareConfig_FAIL_OPEN
}

// l4TargetOptionsToProto converts L4-relevant target options to proto.
func l4TargetOptionsToProto(target *Target) *proto.PathTargetOptions {
	if !target.ProxyProtocol && target.Options.RequestTimeout == 0 && target.Options.SessionIdleTimeout == 0 {
		return nil
	}
	opts := &proto.PathTargetOptions{
		ProxyProtocol: target.ProxyProtocol,
	}
	if target.Options.RequestTimeout > 0 {
		opts.RequestTimeout = durationpb.New(target.Options.RequestTimeout)
	}
	if target.Options.SessionIdleTimeout > 0 {
		opts.SessionIdleTimeout = durationpb.New(target.Options.SessionIdleTimeout)
	}
	return opts
}

func restrictionsToProto(r AccessRestrictions) *proto.AccessRestrictions {
	if len(r.AllowedCIDRs) == 0 && len(r.BlockedCIDRs) == 0 &&
		len(r.AllowedCountries) == 0 && len(r.BlockedCountries) == 0 &&
		r.CrowdSecMode == "" {
		return nil
	}
	return &proto.AccessRestrictions{
		AllowedCidrs:     r.AllowedCIDRs,
		BlockedCidrs:     r.BlockedCIDRs,
		AllowedCountries: r.AllowedCountries,
		BlockedCountries: r.BlockedCountries,
		CrowdsecMode:     r.CrowdSecMode,
	}
}

func (s *Service) Validate() error {
	if s.Name == "" {
		return errors.New("service name is required")
	}
	if len(s.Name) > 255 {
		return errors.New("service name exceeds maximum length of 255 characters")
	}

	if len(s.Targets) == 0 {
		return errors.New("at least one target is required")
	}
	if len(s.PortMappings) > 0 {
		if s.PortMappings[0] == nil {
			return errors.New("port_mappings[0] must not be null")
		}
		s.syncLegacyFields()
	}

	if s.Mode == "" {
		s.Mode = ModeHTTP
	}

	if err := validateHeaderAuths(s.Auth.HeaderAuths); err != nil {
		return err
	}
	if err := validateAccessRestrictions(&s.Restrictions); err != nil {
		return err
	}
	if err := s.validatePrivateRequirements(); err != nil {
		return err
	}
	if len(s.PortMappings) > 0 {
		return s.validatePortMappedL4Mode()
	}

	var err error
	switch s.Mode {
	case ModeHTTP:
		err = s.validateHTTPMode()
	case ModeTCP, ModeUDP:
		err = s.validateTCPUDPMode()
	case ModeTLS:
		err = s.validateTLSMode()
	default:
		return fmt.Errorf("unsupported mode %q", s.Mode)
	}
	if err == nil {
		s.PopulatePortMappingsFromLegacy()
	}
	return err
}

func (s *Service) validatePortMappedL4Mode() error {
	if s.Domain == "" {
		return errors.New("domain is required for L4 services (used for cluster derivation and TLS SNI)")
	}
	if s.isAuthEnabled() {
		return errors.New("auth is not supported for L4 services")
	}
	if len(s.Targets) != 1 {
		return errors.New("L4 services with port_mappings must have exactly one target")
	}
	if err := validatePortMappings(s.PortMappings); err != nil {
		return err
	}
	if s.Targets[0].ProxyProtocol {
		hasTCP := false
		for _, mapping := range s.PortMappings {
			if mapping.Protocol == ModeTCP || mapping.Protocol == ModeTLS {
				hasTCP = true
				break
			}
		}
		if !hasTCP {
			return errors.New("proxy_protocol is not supported for UDP-only services")
		}
	}
	return s.validateL4Target(s.Targets[0])
}

func validatePortMappings(mappings []*PortMapping) error {
	if len(mappings) == 0 {
		return errors.New("port_mappings must contain at least one mapping")
	}

	for i, mapping := range mappings {
		if mapping == nil {
			return fmt.Errorf("port_mappings[%d] must not be null", i)
		}
		switch mapping.Protocol {
		case ModeTCP, ModeUDP, ModeTLS:
		default:
			return fmt.Errorf("port_mappings[%d].protocol %q is not supported", i, mapping.Protocol)
		}
		if mapping.ListenPortStart == 0 || mapping.ListenPortEnd == 0 ||
			mapping.TargetPortStart == 0 || mapping.TargetPortEnd == 0 {
			return fmt.Errorf("port_mappings[%d] ports must be between 1 and 65535", i)
		}
		if mapping.ListenPortStart > mapping.ListenPortEnd {
			return fmt.Errorf("port_mappings[%d] listener range is reversed: %d-%d", i, mapping.ListenPortStart, mapping.ListenPortEnd)
		}
		if mapping.TargetPortStart > mapping.TargetPortEnd {
			return fmt.Errorf("port_mappings[%d] target range is reversed: %d-%d", i, mapping.TargetPortStart, mapping.TargetPortEnd)
		}
		listenSize := uint32(mapping.ListenPortEnd) - uint32(mapping.ListenPortStart)
		targetSize := uint32(mapping.TargetPortEnd) - uint32(mapping.TargetPortStart)
		if listenSize != targetSize {
			return fmt.Errorf(
				"port_mappings[%d] listener range %d-%d and target range %d-%d must contain the same number of ports",
				i,
				mapping.ListenPortStart,
				mapping.ListenPortEnd,
				mapping.TargetPortStart,
				mapping.TargetPortEnd,
			)
		}

		for j := 0; j < i; j++ {
			other := mappings[j]
			if other == nil || other.Protocol != mapping.Protocol {
				continue
			}
			if rangesOverlap(mapping.ListenPortStart, mapping.ListenPortEnd, other.ListenPortStart, other.ListenPortEnd) {
				return fmt.Errorf(
					"port_mappings[%d] listener range %d-%d overlaps port_mappings[%d] range %d-%d for protocol %s",
					i,
					mapping.ListenPortStart,
					mapping.ListenPortEnd,
					j,
					other.ListenPortStart,
					other.ListenPortEnd,
					mapping.Protocol,
				)
			}
		}
	}
	return nil
}

func rangesOverlap(startA, endA, startB, endB uint16) bool {
	return startA <= endB && startB <= endA
}

// validatePrivateRequirements enforces the private-service contract: HTTP mode, ≥1 access group, no bearer auth.
func (s *Service) validatePrivateRequirements() error {
	if !s.Private {
		return nil
	}
	if s.Mode != "" && s.Mode != ModeHTTP {
		return fmt.Errorf("private services only support HTTP mode, got %q", s.Mode)
	}
	if len(s.AccessGroups) == 0 {
		return errors.New("private services require at least one access group")
	}
	if s.Auth.BearerAuth != nil && s.Auth.BearerAuth.Enabled {
		return errors.New("private services cannot enable bearer auth (SSO): NetBird-only access and SSO are mutually exclusive")
	}
	return nil
}

func (s *Service) validateHTTPMode() error {
	if s.Domain == "" {
		return errors.New("service domain is required")
	}
	if s.ListenPort != 0 {
		return errors.New("listen_port is not supported for HTTP services")
	}
	return s.validateHTTPTargets()
}

func (s *Service) validateTCPUDPMode() error {
	if s.Domain == "" {
		return errors.New("domain is required for TCP/UDP services (used for cluster derivation)")
	}
	if s.isAuthEnabled() {
		return errors.New("auth is not supported for TCP/UDP services")
	}
	if len(s.Targets) != 1 {
		return errors.New("TCP/UDP services must have exactly one target")
	}
	if s.Mode == ModeUDP && s.Targets[0].ProxyProtocol {
		return errors.New("proxy_protocol is not supported for UDP services")
	}
	return s.validateL4Target(s.Targets[0])
}

func (s *Service) validateTLSMode() error {
	if s.Domain == "" {
		return errors.New("domain is required for TLS services (used for SNI matching)")
	}
	if s.isAuthEnabled() {
		return errors.New("auth is not supported for TLS services")
	}
	if s.ListenPort == 0 {
		return errors.New("listen_port is required for TLS services")
	}
	if len(s.Targets) != 1 {
		return errors.New("TLS services must have exactly one target")
	}
	return s.validateL4Target(s.Targets[0])
}

func (s *Service) validateHTTPTargets() error {
	for i, target := range s.Targets {
		switch target.TargetType {
		case TargetTypePeer, TargetTypeHost, TargetTypeDomain:
			// Host is normally overwritten by replaceHostByLookup with the
			// resolved peer IP / resource address; operator-supplied values
			// are honored only when DirectUpstream is set. Validate the
			// override here so misconfigured hosts fail fast at API time.
			if err := validateDirectUpstreamHost(i, target); err != nil {
				return err
			}
		case TargetTypeSubnet:
			if target.Host == "" {
				return fmt.Errorf("target %d has empty host but target_type is %q", i, target.TargetType)
			}
		case TargetTypeCluster:
			if err := validateClusterTarget(i, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("target %d has invalid target_type %q", i, target.TargetType)
		}
		if target.TargetId == "" {
			return fmt.Errorf("target %d has empty target_id", i)
		}
		if target.ProxyProtocol {
			return fmt.Errorf("target %d: proxy_protocol is not supported for HTTP services", i)
		}
		if err := validateTargetOptions(i, &target.Options); err != nil {
			return err
		}
	}

	return nil
}

// validateClusterTarget cluster targets should not have empty hosts and should have direct upstream enabled.
func validateClusterTarget(idx int, target *Target) error {
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return fmt.Errorf("target %d: has empty host", idx)
	}
	if !target.Options.DirectUpstream {
		return fmt.Errorf("target %d: %s has direct upstream disabled", idx, target.Host)
	}
	return validateDirectUpstreamHost(idx, target)
}

// validateDirectUpstreamHost validates the operator-supplied Host on a
// peer/host/domain target when DirectUpstream is set. Empty Host is
// allowed — the lookup fills in the default peer IP / resource address.
// Without DirectUpstream the Host value is silently overwritten by
// replaceHostByLookup, so we don't validate it (preserves the historical
// behaviour where APIs accepted any value and dropped it). Non-empty
// Host with DirectUpstream must look like a hostname or IP and must
// not carry a port (port lives on Target.Port).
func validateDirectUpstreamHost(idx int, target *Target) error {
	if !target.Options.DirectUpstream {
		return nil
	}
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return nil
	}
	if strings.ContainsAny(host, " \t/") {
		return fmt.Errorf("target %d: host %q contains invalid characters", idx, host)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("target %d: host %q must not include a port (set target.port instead)", idx, host)
	}
	return nil
}

func (s *Service) validateL4Target(target *Target) error {
	// L4 services have a single target; per-target disable is meaningless
	// (use the service-level Enabled flag instead). Force it on so that
	// buildPathMappings always includes the target in the proto.
	target.Enabled = true

	if target.TargetId == "" {
		return errors.New("target_id is required for L4 services")
	}
	// Cluster targets resolve their upstream host:port from the target's
	// own Host/Port fields just like the other L4 types — buildPathMappings
	// emits net.JoinHostPort(target.Host, target.Port) for every L4
	// target, so allowing port=0 here would let ":0" reach the proxy.
	if target.Port == 0 {
		return errors.New("target port is required for L4 services")
	}
	switch target.TargetType {
	case TargetTypePeer, TargetTypeHost, TargetTypeDomain:
		if err := validateDirectUpstreamHost(0, target); err != nil {
			return err
		}
	case TargetTypeSubnet:
		if target.Host == "" {
			return errors.New("target host is required for subnet targets")
		}
	case TargetTypeCluster:
		// target_id carries the cluster address; the proxy resolves
		// the upstream at request time.
	default:
		return fmt.Errorf("invalid target_type %q for L4 service", target.TargetType)
	}
	if target.Path != nil && *target.Path != "" && *target.Path != "/" {
		return errors.New("path is not supported for L4 services")
	}
	if target.Options.SessionIdleTimeout < 0 {
		return errors.New("session_idle_timeout must be positive for L4 services")
	}
	if target.Options.RequestTimeout < 0 {
		return errors.New("request_timeout must be positive for L4 services")
	}
	if target.Options.SkipTLSVerify {
		return errors.New("skip_tls_verify is not supported for L4 services")
	}
	if target.Options.PathRewrite != "" {
		return errors.New("path_rewrite is not supported for L4 services")
	}
	if len(target.Options.CustomHeaders) > 0 {
		return errors.New("custom_headers is not supported for L4 services")
	}
	return nil
}

// Service mode constants.
const (
	ModeHTTP = "http"
	ModeTCP  = "tcp"
	ModeUDP  = "udp"
	ModeTLS  = "tls"
)

// Target protocol constants (URL scheme for backend connections).
const (
	TargetProtoHTTP  = "http"
	TargetProtoHTTPS = "https"
	TargetProtoTCP   = "tcp"
	TargetProtoUDP   = "udp"
)

// IsL4Protocol returns true if the mode requires port-based routing (TCP, UDP, or TLS).
func IsL4Protocol(mode string) bool {
	return mode == ModeTCP || mode == ModeUDP || mode == ModeTLS
}

// IsPortBasedProtocol returns true if the mode relies on dedicated port allocation.
// TLS is excluded because it uses SNI routing and can share ports with other TLS services.
func IsPortBasedProtocol(mode string) bool {
	return mode == ModeTCP || mode == ModeUDP
}

const (
	maxCustomHeaders  = 16
	maxHeaderKeyLen   = 128
	maxHeaderValueLen = 4096
)

// httpHeaderNameRe matches valid HTTP header field names per RFC 7230 token definition.
var httpHeaderNameRe = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

// hopByHopHeaders are headers that must not be set as custom headers
// because they are connection-level and stripped by the proxy.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// reservedHeaders are set authoritatively by the proxy or control HTTP framing
// and cannot be overridden.
var reservedHeaders = map[string]struct{}{
	"Content-Length":    {},
	"Content-Type":      {},
	"Cookie":            {},
	"Forwarded":         {},
	"X-Forwarded-For":   {},
	"X-Forwarded-Host":  {},
	"X-Forwarded-Port":  {},
	"X-Forwarded-Proto": {},
	"X-Real-Ip":         {},
}

func validateTargetOptions(idx int, opts *TargetOptions) error {
	if opts.PathRewrite != "" && opts.PathRewrite != PathRewritePreserve {
		return fmt.Errorf("target %d: unknown path_rewrite mode %q", idx, opts.PathRewrite)
	}

	if opts.RequestTimeout < 0 {
		return fmt.Errorf("target %d: request_timeout must be positive", idx)
	}

	if opts.SessionIdleTimeout < 0 {
		return fmt.Errorf("target %d: session_idle_timeout must be positive", idx)
	}

	if err := validateCustomHeaders(idx, opts.CustomHeaders); err != nil {
		return err
	}

	return nil
}

func validateCustomHeaders(idx int, headers map[string]string) error {
	if len(headers) > maxCustomHeaders {
		return fmt.Errorf("target %d: custom_headers count %d exceeds maximum of %d", idx, len(headers), maxCustomHeaders)
	}
	seen := make(map[string]string, len(headers))
	for key, value := range headers {
		if !httpHeaderNameRe.MatchString(key) {
			return fmt.Errorf("target %d: custom header key %q is not a valid HTTP header name", idx, key)
		}
		if len(key) > maxHeaderKeyLen {
			return fmt.Errorf("target %d: custom header key %q exceeds maximum length of %d", idx, key, maxHeaderKeyLen)
		}
		if len(value) > maxHeaderValueLen {
			return fmt.Errorf("target %d: custom header %q value exceeds maximum length of %d", idx, key, maxHeaderValueLen)
		}
		if containsCRLF(key) || containsCRLF(value) {
			return fmt.Errorf("target %d: custom header %q contains invalid characters", idx, key)
		}
		canonical := http.CanonicalHeaderKey(key)
		if prev, ok := seen[canonical]; ok {
			return fmt.Errorf("target %d: custom header keys %q and %q collide (both canonicalize to %q)", idx, prev, key, canonical)
		}
		seen[canonical] = key
		if _, ok := hopByHopHeaders[canonical]; ok {
			return fmt.Errorf("target %d: custom header %q is a hop-by-hop header and cannot be set", idx, key)
		}
		if _, ok := reservedHeaders[canonical]; ok {
			return fmt.Errorf("target %d: custom header %q is managed by the proxy and cannot be overridden", idx, key)
		}
		if canonical == "Host" {
			return fmt.Errorf("target %d: use pass_host_header instead of setting Host as a custom header", idx)
		}
	}
	return nil
}

func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func validateHeaderAuths(headers []*HeaderAuthConfig) error {
	for i, h := range headers {
		if h == nil || !h.Enabled {
			continue
		}
		if h.Header == "" {
			return fmt.Errorf("header_auths[%d]: header name is required", i)
		}
		if !httpHeaderNameRe.MatchString(h.Header) {
			return fmt.Errorf("header_auths[%d]: header name %q is not a valid HTTP header name", i, h.Header)
		}
		canonical := http.CanonicalHeaderKey(h.Header)
		if _, ok := hopByHopHeaders[canonical]; ok {
			return fmt.Errorf("header_auths[%d]: header %q is a hop-by-hop header and cannot be used for auth", i, h.Header)
		}
		if _, ok := reservedHeaders[canonical]; ok {
			return fmt.Errorf("header_auths[%d]: header %q is managed by the proxy and cannot be used for auth", i, h.Header)
		}
		if canonical == "Host" {
			return fmt.Errorf("header_auths[%d]: Host header cannot be used for auth", i)
		}
		if len(h.Value) > maxHeaderValueLen {
			return fmt.Errorf("header_auths[%d]: value exceeds maximum length of %d", i, maxHeaderValueLen)
		}
	}
	return nil
}

const (
	maxCIDREntries    = 200
	maxCountryEntries = 50
)

// validateAccessRestrictions validates and normalizes access restriction
// entries. Country codes are uppercased in place.
func validateCrowdSecMode(mode string) error {
	switch mode {
	case "", "off", "enforce", "observe":
		return nil
	default:
		return fmt.Errorf("crowdsec_mode %q is invalid", mode)
	}
}

func validateAccessRestrictions(r *AccessRestrictions) error {
	if err := validateCrowdSecMode(r.CrowdSecMode); err != nil {
		return err
	}

	if len(r.AllowedCIDRs) > maxCIDREntries {
		return fmt.Errorf("allowed_cidrs: exceeds maximum of %d entries", maxCIDREntries)
	}
	if len(r.BlockedCIDRs) > maxCIDREntries {
		return fmt.Errorf("blocked_cidrs: exceeds maximum of %d entries", maxCIDREntries)
	}
	if len(r.AllowedCountries) > maxCountryEntries {
		return fmt.Errorf("allowed_countries: exceeds maximum of %d entries", maxCountryEntries)
	}
	if len(r.BlockedCountries) > maxCountryEntries {
		return fmt.Errorf("blocked_countries: exceeds maximum of %d entries", maxCountryEntries)
	}

	if err := validateCIDRList("allowed_cidrs", r.AllowedCIDRs); err != nil {
		return err
	}
	if err := validateCIDRList("blocked_cidrs", r.BlockedCIDRs); err != nil {
		return err
	}
	if err := normalizeCountryList("allowed_countries", r.AllowedCountries); err != nil {
		return err
	}
	return normalizeCountryList("blocked_countries", r.BlockedCountries)
}

func validateCIDRList(field string, cidrs []string) error {
	for i, raw := range cidrs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		if prefix != prefix.Masked() {
			return fmt.Errorf("%s[%d]: %q has host bits set, use %s instead", field, i, raw, prefix.Masked())
		}
	}
	return nil
}

func normalizeCountryList(field string, codes []string) error {
	for i, code := range codes {
		if len(code) != 2 {
			return fmt.Errorf("%s[%d]: %q must be a 2-letter ISO 3166-1 alpha-2 code", field, i, code)
		}
		codes[i] = strings.ToUpper(code)
	}
	return nil
}

func (s *Service) EventMeta() map[string]any {
	meta := map[string]any{
		"name":          s.Name,
		"domain":        s.Domain,
		"proxy_cluster": s.ProxyCluster,
		"source":        s.Source,
		"auth":          s.isAuthEnabled(),
		"mode":          s.Mode,
	}

	if s.ListenPort != 0 {
		meta["listen_port"] = s.ListenPort
	}
	if len(s.PortMappings) > 0 {
		meta["port_mapping_count"] = len(s.PortMappings)
	}

	if len(s.Targets) > 0 {
		t := s.Targets[0]
		if t.ProxyProtocol {
			meta["proxy_protocol"] = true
		}
		if t.Options.RequestTimeout != 0 {
			meta["request_timeout"] = t.Options.RequestTimeout.String()
		}
		if t.Options.SessionIdleTimeout != 0 {
			meta["session_idle_timeout"] = t.Options.SessionIdleTimeout.String()
		}
	}

	return meta
}

func (s *Service) isAuthEnabled() bool {
	if (s.Auth.PasswordAuth != nil && s.Auth.PasswordAuth.Enabled) ||
		(s.Auth.PinAuth != nil && s.Auth.PinAuth.Enabled) ||
		(s.Auth.BearerAuth != nil && s.Auth.BearerAuth.Enabled) {
		return true
	}
	for _, h := range s.Auth.HeaderAuths {
		if h != nil && h.Enabled {
			return true
		}
	}
	return false
}

func (s *Service) Copy() *Service {
	targets := make([]*Target, len(s.Targets))
	for i, target := range s.Targets {
		targetCopy := *target
		if target.Path != nil {
			p := *target.Path
			targetCopy.Path = &p
		}
		if len(target.Options.CustomHeaders) > 0 {
			targetCopy.Options.CustomHeaders = make(map[string]string, len(target.Options.CustomHeaders))
			for k, v := range target.Options.CustomHeaders {
				targetCopy.Options.CustomHeaders[k] = v
			}
		}
		targets[i] = &targetCopy
	}
	portMappings := make([]*PortMapping, len(s.PortMappings))
	for i, mapping := range s.PortMappings {
		if mapping == nil {
			continue
		}
		mappingCopy := *mapping
		portMappings[i] = &mappingCopy
	}

	authCopy := s.Auth
	if s.Auth.PasswordAuth != nil {
		pa := *s.Auth.PasswordAuth
		authCopy.PasswordAuth = &pa
	}
	if s.Auth.PinAuth != nil {
		pa := *s.Auth.PinAuth
		authCopy.PinAuth = &pa
	}
	if s.Auth.BearerAuth != nil {
		ba := *s.Auth.BearerAuth
		if len(s.Auth.BearerAuth.DistributionGroups) > 0 {
			ba.DistributionGroups = make([]string, len(s.Auth.BearerAuth.DistributionGroups))
			copy(ba.DistributionGroups, s.Auth.BearerAuth.DistributionGroups)
		}
		authCopy.BearerAuth = &ba
	}
	if len(s.Auth.HeaderAuths) > 0 {
		authCopy.HeaderAuths = make([]*HeaderAuthConfig, len(s.Auth.HeaderAuths))
		for i, h := range s.Auth.HeaderAuths {
			if h == nil {
				continue
			}
			hCopy := *h
			authCopy.HeaderAuths[i] = &hCopy
		}
	}

	var accessGroups []string
	if len(s.AccessGroups) > 0 {
		accessGroups = append([]string(nil), s.AccessGroups...)
	}

	serviceCopy := &Service{
		ID:                s.ID,
		AccountID:         s.AccountID,
		Name:              s.Name,
		Domain:            s.Domain,
		ProxyCluster:      s.ProxyCluster,
		Targets:           targets,
		PortMappings:      portMappings,
		Enabled:           s.Enabled,
		Terminated:        s.Terminated,
		PassHostHeader:    s.PassHostHeader,
		RewriteRedirects:  s.RewriteRedirects,
		Auth:              authCopy,
		Restrictions:      s.Restrictions.Copy(),
		Meta:              s.Meta,
		SessionPrivateKey: s.SessionPrivateKey,
		SessionPublicKey:  s.SessionPublicKey,
		Source:            s.Source,
		SourcePeer:        s.SourcePeer,
		Mode:              s.Mode,
		ListenPort:        s.ListenPort,
		PortAutoAssigned:  s.PortAutoAssigned,
		Private:           s.Private,
		AccessGroups:      accessGroups,
		PortMappingsSet:   s.PortMappingsSet,
	}
	if s.HTTPDomain != nil {
		httpDomain := *s.HTTPDomain
		serviceCopy.HTTPDomain = &httpDomain
	}
	serviceCopy.preparePortMappings()
	return serviceCopy
}

func (s *Service) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	if s.SessionPrivateKey != "" {
		var err error
		s.SessionPrivateKey, err = enc.Encrypt(s.SessionPrivateKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	if s.SessionPrivateKey != "" {
		var err error
		s.SessionPrivateKey, err = enc.Decrypt(s.SessionPrivateKey)
		if err != nil {
			return err
		}
	}

	return nil
}

var pinRegexp = regexp.MustCompile(`^\d{6}$`)

const alphanumCharset = "abcdefghijklmnopqrstuvwxyz0123456789"

var validNamePrefix = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ExposeServiceRequest contains the parameters for creating a peer-initiated expose service.
type ExposeServiceRequest struct {
	NamePrefix string
	Port       uint16
	Mode       string
	// TargetProtocol is the protocol used to connect to the peer backend.
	// For HTTP mode: "http" (default) or "https". For L4 modes: "tcp" or "udp".
	TargetProtocol string
	Domain         string
	Pin            string
	Password       string
	UserGroups     []string
	ListenPort     uint16
}

// Validate checks all fields of the expose request.
func (r *ExposeServiceRequest) Validate() error {
	if r == nil {
		return errors.New("request cannot be nil")
	}

	if r.Port == 0 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", r.Port)
	}

	switch r.Mode {
	case ModeHTTP, ModeTCP, ModeUDP, ModeTLS:
	default:
		return fmt.Errorf("unsupported mode %q", r.Mode)
	}

	if IsL4Protocol(r.Mode) {
		if r.Pin != "" || r.Password != "" || len(r.UserGroups) > 0 {
			return fmt.Errorf("authentication is not supported for %s mode", r.Mode)
		}
	}

	if r.Pin != "" && !pinRegexp.MatchString(r.Pin) {
		return errors.New("invalid pin: must be exactly 6 digits")
	}

	for _, g := range r.UserGroups {
		if g == "" {
			return errors.New("user group name cannot be empty")
		}
	}

	if r.NamePrefix != "" && !validNamePrefix.MatchString(r.NamePrefix) {
		return fmt.Errorf("invalid name prefix %q: must be lowercase alphanumeric with optional hyphens, 1-32 characters", r.NamePrefix)
	}

	return nil
}

// ToService builds a Service from the expose request.
func (r *ExposeServiceRequest) ToService(accountID, peerID, serviceName string) *Service {
	svc := &Service{
		AccountID: accountID,
		Name:      serviceName,
		Mode:      r.Mode,
		Enabled:   true,
	}

	// If domain is empty, CreateServiceFromPeer generates a unique subdomain.
	// When explicitly provided, the service name is prepended as a subdomain.
	if r.Domain != "" {
		svc.Domain = serviceName + "." + r.Domain
	}

	if IsL4Protocol(r.Mode) {
		svc.ListenPort = r.Port
		if r.ListenPort > 0 {
			svc.ListenPort = r.ListenPort
		}
	}

	var targetProto string
	switch {
	case !IsL4Protocol(r.Mode):
		targetProto = TargetProtoHTTP
		if r.TargetProtocol != "" {
			targetProto = r.TargetProtocol
		}
	case r.Mode == ModeUDP:
		targetProto = TargetProtoUDP
	default:
		targetProto = TargetProtoTCP
	}
	svc.Targets = []*Target{
		{
			AccountID:  accountID,
			Port:       r.Port,
			Protocol:   targetProto,
			TargetId:   peerID,
			TargetType: TargetTypePeer,
			Enabled:    true,
		},
	}
	svc.PopulatePortMappingsFromLegacy()

	if r.Pin != "" {
		svc.Auth.PinAuth = &PINAuthConfig{
			Enabled: true,
			Pin:     r.Pin,
		}
	}

	if r.Password != "" {
		svc.Auth.PasswordAuth = &PasswordAuthConfig{
			Enabled:  true,
			Password: r.Password,
		}
	}

	if len(r.UserGroups) > 0 {
		svc.Auth.BearerAuth = &BearerAuthConfig{
			Enabled:            true,
			DistributionGroups: r.UserGroups,
		}
	}

	return svc
}

// ExposeServiceResponse contains the result of a successful peer expose creation.
type ExposeServiceResponse struct {
	ServiceName      string
	ServiceURL       string
	Domain           string
	PortAutoAssigned bool
}

// GenerateExposeName generates a random service name for peer-exposed services.
// The prefix, if provided, must be a valid DNS label component (lowercase alphanumeric and hyphens).
func GenerateExposeName(prefix string) (string, error) {
	if prefix != "" && !validNamePrefix.MatchString(prefix) {
		return "", fmt.Errorf("invalid name prefix %q: must be lowercase alphanumeric with optional hyphens, 1-32 characters", prefix)
	}

	suffixLen := 12
	if prefix != "" {
		suffixLen = 4
	}

	suffix, err := randomAlphanumeric(suffixLen)
	if err != nil {
		return "", fmt.Errorf("generate random name: %w", err)
	}

	if prefix == "" {
		return suffix, nil
	}
	return prefix + "-" + suffix, nil
}

func randomAlphanumeric(n int) (string, error) {
	result := make([]byte, n)
	charsetLen := big.NewInt(int64(len(alphanumCharset)))
	for i := range result {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = alphanumCharset[idx.Int64()]
	}
	return string(result), nil
}
