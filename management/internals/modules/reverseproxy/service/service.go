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

	TargetTypePeer   TargetType = "peer"
	TargetTypeHost   TargetType = "host"
	TargetTypeDomain TargetType = "domain"
	TargetTypeSubnet TargetType = "subnet"

	SourcePermanent = "permanent"
	SourceEphemeral = "ephemeral"
)

type TargetOptions struct {
	SkipTLSVerify      bool              `json:"skip_tls_verify"`
	RequestTimeout     time.Duration     `json:"request_timeout,omitempty"`
	SessionIdleTimeout time.Duration     `json:"session_idle_timeout,omitempty"`
	PathRewrite        PathRewriteMode   `json:"path_rewrite,omitempty"`
	CustomHeaders      map[string]string `gorm:"serializer:json" json:"custom_headers,omitempty"`
}

type Target struct {
	ID            uint          `gorm:"primaryKey" json:"-"`
	AccountID     string        `gorm:"index:idx_target_account;not null" json:"-"`
	ServiceID     string        `gorm:"index:idx_service_targets;not null" json:"-"`
	Path          *string       `json:"path,omitempty"`
	Host          string        `json:"host"` // the Host field is only used for subnet targets, otherwise ignored
	Port          uint16        `gorm:"index:idx_target_port" json:"port"`
	Protocol      string        `gorm:"index:idx_target_protocol" json:"protocol"`
	TargetId      string        `gorm:"index:idx_target_id" json:"target_id"`
	TargetType    TargetType    `gorm:"index:idx_target_type" json:"target_type"`
	Enabled       bool          `gorm:"index:idx_target_enabled" json:"enabled"`
	Options       TargetOptions `gorm:"embedded" json:"options"`
	ProxyProtocol bool          `json:"proxy_protocol"`
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
}

// Copy returns a deep copy of the AccessRestrictions.
func (r AccessRestrictions) Copy() AccessRestrictions {
	return AccessRestrictions{
		AllowedCIDRs:     slices.Clone(r.AllowedCIDRs),
		BlockedCIDRs:     slices.Clone(r.BlockedCIDRs),
		AllowedCountries: slices.Clone(r.AllowedCountries),
		BlockedCountries: slices.Clone(r.BlockedCountries),
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
	Domain            string    `gorm:"type:varchar(255);uniqueIndex"`
	ProxyCluster      string    `gorm:"index"`
	Targets           []*Target `gorm:"foreignKey:ServiceID;constraint:OnDelete:CASCADE"`
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
}

func (s *Service) ToAPIResponse() *api.Service {
	authConfig := api.ServiceAuthConfig{}

	if s.Auth.PasswordAuth != nil {
		authConfig.PasswordAuth = &api.PasswordAuthConfig{
			Enabled: s.Auth.PasswordAuth.Enabled,
		}
	}

	if s.Auth.PinAuth != nil {
		authConfig.PinAuth = &api.PINAuthConfig{
			Enabled: s.Auth.PinAuth.Enabled,
		}
	}

	if s.Auth.BearerAuth != nil {
		authConfig.BearerAuth = &api.BearerAuthConfig{
			Enabled:            s.Auth.BearerAuth.Enabled,
			DistributionGroups: &s.Auth.BearerAuth.DistributionGroups,
		}
	}

	if len(s.Auth.HeaderAuths) > 0 {
		apiHeaders := make([]api.HeaderAuthConfig, 0, len(s.Auth.HeaderAuths))
		for _, h := range s.Auth.HeaderAuths {
			if h == nil {
				continue
			}
			apiHeaders = append(apiHeaders, api.HeaderAuthConfig{
				Enabled: h.Enabled,
				Header:  h.Header,
			})
		}
		authConfig.HeaderAuths = &apiHeaders
	}

	// Convert internal targets to API targets
	apiTargets := make([]api.ServiceTarget, 0, len(s.Targets))
	for _, target := range s.Targets {
		st := api.ServiceTarget{
			Path:       target.Path,
			Host:       &target.Host,
			Port:       int(target.Port),
			Protocol:   api.ServiceTargetProtocol(target.Protocol),
			TargetId:   target.TargetId,
			TargetType: api.ServiceTargetTargetType(target.TargetType),
			Enabled:    target.Enabled && !s.Terminated,
		}
		opts := targetOptionsToAPI(target.Options)
		if opts == nil {
			opts = &api.ServiceTargetOptions{}
		}
		if target.ProxyProtocol {
			opts.ProxyProtocol = &target.ProxyProtocol
		}
		st.Options = opts
		apiTargets = append(apiTargets, st)
	}

	meta := api.ServiceMeta{
		CreatedAt: s.Meta.CreatedAt,
		Status:    api.ServiceMetaStatus(s.Meta.Status),
	}

	if s.Meta.CertificateIssuedAt != nil {
		meta.CertificateIssuedAt = s.Meta.CertificateIssuedAt
	}

	mode := api.ServiceMode(s.Mode)
	listenPort := int(s.ListenPort)

	resp := &api.Service{
		Id:                 s.ID,
		Name:               s.Name,
		Domain:             s.Domain,
		Targets:            apiTargets,
		Enabled:            s.Enabled && !s.Terminated,
		Terminated:         &s.Terminated,
		PassHostHeader:     &s.PassHostHeader,
		RewriteRedirects:   &s.RewriteRedirects,
		Auth:               authConfig,
		AccessRestrictions: restrictionsToAPI(s.Restrictions),
		Meta:               meta,
		Mode:               &mode,
		ListenPort:         &listenPort,
		PortAutoAssigned:   &s.PortAutoAssigned,
	}

	if s.ProxyCluster != "" {
		resp.ProxyCluster = &s.ProxyCluster
	}

	return resp
}

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
		targetURL := url.URL{
			Scheme: target.Protocol,
			Host:   target.Host,
			Path:   "/",
		}
		if target.Port > 0 && !isDefaultPort(target.Protocol, target.Port) {
			targetURL.Host = net.JoinHostPort(targetURL.Host, strconv.FormatUint(uint64(target.Port), 10))
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

func targetOptionsToAPI(opts TargetOptions) *api.ServiceTargetOptions {
	if !opts.SkipTLSVerify && opts.RequestTimeout == 0 && opts.SessionIdleTimeout == 0 && opts.PathRewrite == "" && len(opts.CustomHeaders) == 0 {
		return nil
	}
	apiOpts := &api.ServiceTargetOptions{}
	if opts.SkipTLSVerify {
		apiOpts.SkipTlsVerify = &opts.SkipTLSVerify
	}
	if opts.RequestTimeout != 0 {
		s := opts.RequestTimeout.String()
		apiOpts.RequestTimeout = &s
	}
	if opts.SessionIdleTimeout != 0 {
		s := opts.SessionIdleTimeout.String()
		apiOpts.SessionIdleTimeout = &s
	}
	if opts.PathRewrite != "" {
		pr := api.ServiceTargetOptionsPathRewrite(opts.PathRewrite)
		apiOpts.PathRewrite = &pr
	}
	if len(opts.CustomHeaders) > 0 {
		apiOpts.CustomHeaders = &opts.CustomHeaders
	}
	return apiOpts
}

func targetOptionsToProto(opts TargetOptions) *proto.PathTargetOptions {
	if !opts.SkipTLSVerify && opts.PathRewrite == "" && opts.RequestTimeout == 0 && len(opts.CustomHeaders) == 0 {
		return nil
	}
	popts := &proto.PathTargetOptions{
		SkipTlsVerify: opts.SkipTLSVerify,
		PathRewrite:   pathRewriteToProto(opts.PathRewrite),
		CustomHeaders: opts.CustomHeaders,
	}
	if opts.RequestTimeout != 0 {
		popts.RequestTimeout = durationpb.New(opts.RequestTimeout)
	}
	return popts
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

func targetOptionsFromAPI(idx int, o *api.ServiceTargetOptions) (TargetOptions, error) {
	var opts TargetOptions
	if o.SkipTlsVerify != nil {
		opts.SkipTLSVerify = *o.SkipTlsVerify
	}
	if o.RequestTimeout != nil {
		d, err := time.ParseDuration(*o.RequestTimeout)
		if err != nil {
			return opts, fmt.Errorf("target %d: parse request_timeout %q: %w", idx, *o.RequestTimeout, err)
		}
		opts.RequestTimeout = d
	}
	if o.SessionIdleTimeout != nil {
		d, err := time.ParseDuration(*o.SessionIdleTimeout)
		if err != nil {
			return opts, fmt.Errorf("target %d: parse session_idle_timeout %q: %w", idx, *o.SessionIdleTimeout, err)
		}
		opts.SessionIdleTimeout = d
	}
	if o.PathRewrite != nil {
		opts.PathRewrite = PathRewriteMode(*o.PathRewrite)
	}
	if o.CustomHeaders != nil {
		opts.CustomHeaders = *o.CustomHeaders
	}
	return opts, nil
}

func (s *Service) FromAPIRequest(req *api.ServiceRequest, accountID string) error {
	s.Name = req.Name
	s.Domain = req.Domain
	s.AccountID = accountID

	if req.Mode != nil {
		s.Mode = string(*req.Mode)
	}
	if req.ListenPort != nil {
		s.ListenPort = uint16(*req.ListenPort) //nolint:gosec
	}

	targets, err := targetsFromAPI(accountID, req.Targets)
	if err != nil {
		return err
	}
	s.Targets = targets
	s.Enabled = req.Enabled

	if req.PassHostHeader != nil {
		s.PassHostHeader = *req.PassHostHeader
	}
	if req.RewriteRedirects != nil {
		s.RewriteRedirects = *req.RewriteRedirects
	}

	if req.Auth != nil {
		s.Auth = authFromAPI(req.Auth)
	}

	if req.AccessRestrictions != nil {
		s.Restrictions = restrictionsFromAPI(req.AccessRestrictions)
	}

	return nil
}

func targetsFromAPI(accountID string, apiTargetsPtr *[]api.ServiceTarget) ([]*Target, error) {
	var apiTargets []api.ServiceTarget
	if apiTargetsPtr != nil {
		apiTargets = *apiTargetsPtr
	}

	targets := make([]*Target, 0, len(apiTargets))
	for i, apiTarget := range apiTargets {
		target := &Target{
			AccountID:  accountID,
			Path:       apiTarget.Path,
			Port:       uint16(apiTarget.Port), //nolint:gosec // validated by API layer
			Protocol:   string(apiTarget.Protocol),
			TargetId:   apiTarget.TargetId,
			TargetType: TargetType(apiTarget.TargetType),
			Enabled:    apiTarget.Enabled,
		}
		if apiTarget.Host != nil {
			target.Host = *apiTarget.Host
		}
		if apiTarget.Options != nil {
			opts, err := targetOptionsFromAPI(i, apiTarget.Options)
			if err != nil {
				return nil, err
			}
			target.Options = opts
			if apiTarget.Options.ProxyProtocol != nil {
				target.ProxyProtocol = *apiTarget.Options.ProxyProtocol
			}
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func authFromAPI(reqAuth *api.ServiceAuthConfig) AuthConfig {
	var auth AuthConfig
	if reqAuth.PasswordAuth != nil {
		auth.PasswordAuth = &PasswordAuthConfig{
			Enabled:  reqAuth.PasswordAuth.Enabled,
			Password: reqAuth.PasswordAuth.Password,
		}
	}
	if reqAuth.PinAuth != nil {
		auth.PinAuth = &PINAuthConfig{
			Enabled: reqAuth.PinAuth.Enabled,
			Pin:     reqAuth.PinAuth.Pin,
		}
	}
	if reqAuth.BearerAuth != nil {
		bearerAuth := &BearerAuthConfig{
			Enabled: reqAuth.BearerAuth.Enabled,
		}
		if reqAuth.BearerAuth.DistributionGroups != nil {
			bearerAuth.DistributionGroups = *reqAuth.BearerAuth.DistributionGroups
		}
		auth.BearerAuth = bearerAuth
	}
	if reqAuth.HeaderAuths != nil {
		for _, h := range *reqAuth.HeaderAuths {
			auth.HeaderAuths = append(auth.HeaderAuths, &HeaderAuthConfig{
				Enabled: h.Enabled,
				Header:  h.Header,
				Value:   h.Value,
			})
		}
	}
	return auth
}

func restrictionsFromAPI(r *api.AccessRestrictions) AccessRestrictions {
	if r == nil {
		return AccessRestrictions{}
	}
	var res AccessRestrictions
	if r.AllowedCidrs != nil {
		res.AllowedCIDRs = *r.AllowedCidrs
	}
	if r.BlockedCidrs != nil {
		res.BlockedCIDRs = *r.BlockedCidrs
	}
	if r.AllowedCountries != nil {
		res.AllowedCountries = *r.AllowedCountries
	}
	if r.BlockedCountries != nil {
		res.BlockedCountries = *r.BlockedCountries
	}
	return res
}

func restrictionsToAPI(r AccessRestrictions) *api.AccessRestrictions {
	if len(r.AllowedCIDRs) == 0 && len(r.BlockedCIDRs) == 0 && len(r.AllowedCountries) == 0 && len(r.BlockedCountries) == 0 {
		return nil
	}
	res := &api.AccessRestrictions{}
	if len(r.AllowedCIDRs) > 0 {
		res.AllowedCidrs = &r.AllowedCIDRs
	}
	if len(r.BlockedCIDRs) > 0 {
		res.BlockedCidrs = &r.BlockedCIDRs
	}
	if len(r.AllowedCountries) > 0 {
		res.AllowedCountries = &r.AllowedCountries
	}
	if len(r.BlockedCountries) > 0 {
		res.BlockedCountries = &r.BlockedCountries
	}
	return res
}

func restrictionsToProto(r AccessRestrictions) *proto.AccessRestrictions {
	if len(r.AllowedCIDRs) == 0 && len(r.BlockedCIDRs) == 0 && len(r.AllowedCountries) == 0 && len(r.BlockedCountries) == 0 {
		return nil
	}
	return &proto.AccessRestrictions{
		AllowedCidrs:     r.AllowedCIDRs,
		BlockedCidrs:     r.BlockedCIDRs,
		AllowedCountries: r.AllowedCountries,
		BlockedCountries: r.BlockedCountries,
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

	if s.Mode == "" {
		s.Mode = ModeHTTP
	}

	if err := validateHeaderAuths(s.Auth.HeaderAuths); err != nil {
		return err
	}
	if err := validateAccessRestrictions(&s.Restrictions); err != nil {
		return err
	}

	switch s.Mode {
	case ModeHTTP:
		return s.validateHTTPMode()
	case ModeTCP, ModeUDP:
		return s.validateTCPUDPMode()
	case ModeTLS:
		return s.validateTLSMode()
	default:
		return fmt.Errorf("unsupported mode %q", s.Mode)
	}
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
			// host field will be ignored
		case TargetTypeSubnet:
			if target.Host == "" {
				return fmt.Errorf("target %d has empty host but target_type is %q", i, target.TargetType)
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

func (s *Service) validateL4Target(target *Target) error {
	// L4 services have a single target; per-target disable is meaningless
	// (use the service-level Enabled flag instead). Force it on so that
	// buildPathMappings always includes the target in the proto.
	target.Enabled = true

	if target.Port == 0 {
		return errors.New("target port is required for L4 services")
	}
	if target.TargetId == "" {
		return errors.New("target_id is required for L4 services")
	}
	switch target.TargetType {
	case TargetTypePeer, TargetTypeHost, TargetTypeDomain:
		// OK
	case TargetTypeSubnet:
		if target.Host == "" {
			return errors.New("target host is required for subnet targets")
		}
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
func validateAccessRestrictions(r *AccessRestrictions) error {
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

	for i, raw := range r.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("allowed_cidrs[%d]: %w", i, err)
		}
		if prefix != prefix.Masked() {
			return fmt.Errorf("allowed_cidrs[%d]: %q has host bits set, use %s instead", i, raw, prefix.Masked())
		}
	}
	for i, raw := range r.BlockedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("blocked_cidrs[%d]: %w", i, err)
		}
		if prefix != prefix.Masked() {
			return fmt.Errorf("blocked_cidrs[%d]: %q has host bits set, use %s instead", i, raw, prefix.Masked())
		}
	}
	for i, code := range r.AllowedCountries {
		if len(code) != 2 {
			return fmt.Errorf("allowed_countries[%d]: %q must be a 2-letter ISO 3166-1 alpha-2 code", i, code)
		}
		r.AllowedCountries[i] = strings.ToUpper(code)
	}
	for i, code := range r.BlockedCountries {
		if len(code) != 2 {
			return fmt.Errorf("blocked_countries[%d]: %q must be a 2-letter ISO 3166-1 alpha-2 code", i, code)
		}
		r.BlockedCountries[i] = strings.ToUpper(code)
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

	return &Service{
		ID:                s.ID,
		AccountID:         s.AccountID,
		Name:              s.Name,
		Domain:            s.Domain,
		ProxyCluster:      s.ProxyCluster,
		Targets:           targets,
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
	}
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
