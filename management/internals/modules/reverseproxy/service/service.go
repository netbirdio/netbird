package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
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

const (
	StatusPending            Status = "pending"
	StatusActive             Status = "active"
	StatusTunnelNotCreated   Status = "tunnel_not_created"
	StatusCertificatePending Status = "certificate_pending"
	StatusCertificateFailed  Status = "certificate_failed"
	StatusError              Status = "error"

	TargetTypePeer   = "peer"
	TargetTypeHost   = "host"
	TargetTypeDomain = "domain"
	TargetTypeSubnet = "subnet"

	SourcePermanent = "permanent"
	SourceEphemeral = "ephemeral"
)

type TargetOptions struct {
	SkipTLSVerify  bool              `json:"skip_tls_verify"`
	RequestTimeout time.Duration     `json:"request_timeout,omitempty"`
	PathRewrite    PathRewriteMode   `json:"path_rewrite,omitempty"`
	CustomHeaders  map[string]string `gorm:"serializer:json" json:"custom_headers,omitempty"`
}

type Target struct {
	ID         uint          `gorm:"primaryKey" json:"-"`
	AccountID  string        `gorm:"index:idx_target_account;not null" json:"-"`
	ServiceID  string        `gorm:"index:idx_service_targets;not null" json:"-"`
	Path       *string       `json:"path,omitempty"`
	Host       string        `json:"host"` // the Host field is only used for subnet targets, otherwise ignored
	Port       int           `gorm:"index:idx_target_port" json:"port"`
	Protocol   string        `gorm:"index:idx_target_protocol" json:"protocol"`
	TargetId   string        `gorm:"index:idx_target_id" json:"target_id"`
	TargetType string        `gorm:"index:idx_target_type" json:"target_type"`
	Enabled    bool          `gorm:"index:idx_target_enabled" json:"enabled"`
	Options    TargetOptions `gorm:"embedded" json:"options"`
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

type AuthConfig struct {
	PasswordAuth *PasswordAuthConfig `json:"password_auth,omitempty" gorm:"serializer:json"`
	PinAuth      *PINAuthConfig      `json:"pin_auth,omitempty" gorm:"serializer:json"`
	BearerAuth   *BearerAuthConfig   `json:"bearer_auth,omitempty" gorm:"serializer:json"`
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

	return nil
}

func (a *AuthConfig) ClearSecrets() {
	if a.PasswordAuth != nil {
		a.PasswordAuth.Password = ""
	}
	if a.PinAuth != nil {
		a.PinAuth.Pin = ""
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
	Domain            string    `gorm:"index"`
	ProxyCluster      string    `gorm:"index"`
	Targets           []*Target `gorm:"foreignKey:ServiceID;constraint:OnDelete:CASCADE"`
	Enabled           bool
	PassHostHeader    bool
	RewriteRedirects  bool
	Auth              AuthConfig `gorm:"serializer:json"`
	Meta              Meta       `gorm:"embedded;embeddedPrefix:meta_"`
	SessionPrivateKey string     `gorm:"column:session_private_key"`
	SessionPublicKey  string     `gorm:"column:session_public_key"`
	Source            string     `gorm:"default:'permanent'"`
	SourcePeer        string
}

func NewService(accountID, name, domain, proxyCluster string, targets []*Target, enabled bool) *Service {
	for _, target := range targets {
		target.AccountID = accountID
	}

	s := &Service{
		AccountID:    accountID,
		Name:         name,
		Domain:       domain,
		ProxyCluster: proxyCluster,
		Targets:      targets,
		Enabled:      enabled,
	}
	s.InitNewRecord()
	return s
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
	s.Auth.ClearSecrets()

	authConfig := api.ServiceAuthConfig{}

	if s.Auth.PasswordAuth != nil {
		authConfig.PasswordAuth = &api.PasswordAuthConfig{
			Enabled:  s.Auth.PasswordAuth.Enabled,
			Password: s.Auth.PasswordAuth.Password,
		}
	}

	if s.Auth.PinAuth != nil {
		authConfig.PinAuth = &api.PINAuthConfig{
			Enabled: s.Auth.PinAuth.Enabled,
			Pin:     s.Auth.PinAuth.Pin,
		}
	}

	if s.Auth.BearerAuth != nil {
		authConfig.BearerAuth = &api.BearerAuthConfig{
			Enabled:            s.Auth.BearerAuth.Enabled,
			DistributionGroups: &s.Auth.BearerAuth.DistributionGroups,
		}
	}

	// Convert internal targets to API targets
	apiTargets := make([]api.ServiceTarget, 0, len(s.Targets))
	for _, target := range s.Targets {
		st := api.ServiceTarget{
			Path:       target.Path,
			Host:       &target.Host,
			Port:       target.Port,
			Protocol:   api.ServiceTargetProtocol(target.Protocol),
			TargetId:   target.TargetId,
			TargetType: api.ServiceTargetTargetType(target.TargetType),
			Enabled:    target.Enabled,
		}
		st.Options = targetOptionsToAPI(target.Options)
		apiTargets = append(apiTargets, st)
	}

	meta := api.ServiceMeta{
		CreatedAt: s.Meta.CreatedAt,
		Status:    api.ServiceMetaStatus(s.Meta.Status),
	}

	if s.Meta.CertificateIssuedAt != nil {
		meta.CertificateIssuedAt = s.Meta.CertificateIssuedAt
	}

	resp := &api.Service{
		Id:               s.ID,
		Name:             s.Name,
		Domain:           s.Domain,
		Targets:          apiTargets,
		Enabled:          s.Enabled,
		PassHostHeader:   &s.PassHostHeader,
		RewriteRedirects: &s.RewriteRedirects,
		Auth:             authConfig,
		Meta:             meta,
	}

	if s.ProxyCluster != "" {
		resp.ProxyCluster = &s.ProxyCluster
	}

	return resp
}

func (s *Service) ToProtoMapping(operation Operation, authToken string, oidcConfig proxy.OIDCValidationConfig) *proto.ProxyMapping {
	pathMappings := make([]*proto.PathMapping, 0, len(s.Targets))
	for _, target := range s.Targets {
		if !target.Enabled {
			continue
		}

		// TODO: Make path prefix stripping configurable per-target.
		// Currently the matching prefix is baked into the target URL path,
		// so the proxy strips-then-re-adds it (effectively a no-op).
		targetURL := url.URL{
			Scheme: target.Protocol,
			Host:   target.Host,
			Path:   "/", // TODO: support service path
		}
		if target.Port > 0 && !isDefaultPort(target.Protocol, target.Port) {
			targetURL.Host = net.JoinHostPort(targetURL.Host, strconv.Itoa(target.Port))
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

	return &proto.ProxyMapping{
		Type:             operationToProtoType(operation),
		Id:               s.ID,
		Domain:           s.Domain,
		Path:             pathMappings,
		AuthToken:        authToken,
		Auth:             auth,
		AccountId:        s.AccountID,
		PassHostHeader:   s.PassHostHeader,
		RewriteRedirects: s.RewriteRedirects,
	}
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
		log.Fatalf("unknown operation type: %v", op)
		return proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED
	}
}

// isDefaultPort reports whether port is the standard default for the given scheme
// (443 for https, 80 for http).
func isDefaultPort(scheme string, port int) bool {
	return (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
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
	if !opts.SkipTLSVerify && opts.RequestTimeout == 0 && opts.PathRewrite == "" && len(opts.CustomHeaders) == 0 {
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

	targets := make([]*Target, 0, len(req.Targets))
	for i, apiTarget := range req.Targets {
		target := &Target{
			AccountID:  accountID,
			Path:       apiTarget.Path,
			Port:       apiTarget.Port,
			Protocol:   string(apiTarget.Protocol),
			TargetId:   apiTarget.TargetId,
			TargetType: string(apiTarget.TargetType),
			Enabled:    apiTarget.Enabled,
		}
		if apiTarget.Host != nil {
			target.Host = *apiTarget.Host
		}
		if apiTarget.Options != nil {
			opts, err := targetOptionsFromAPI(i, apiTarget.Options)
			if err != nil {
				return err
			}
			target.Options = opts
		}
		targets = append(targets, target)
	}
	s.Targets = targets

	s.Enabled = req.Enabled

	if req.PassHostHeader != nil {
		s.PassHostHeader = *req.PassHostHeader
	}

	if req.RewriteRedirects != nil {
		s.RewriteRedirects = *req.RewriteRedirects
	}

	if req.Auth.PasswordAuth != nil {
		s.Auth.PasswordAuth = &PasswordAuthConfig{
			Enabled:  req.Auth.PasswordAuth.Enabled,
			Password: req.Auth.PasswordAuth.Password,
		}
	}

	if req.Auth.PinAuth != nil {
		s.Auth.PinAuth = &PINAuthConfig{
			Enabled: req.Auth.PinAuth.Enabled,
			Pin:     req.Auth.PinAuth.Pin,
		}
	}

	if req.Auth.BearerAuth != nil {
		bearerAuth := &BearerAuthConfig{
			Enabled: req.Auth.BearerAuth.Enabled,
		}
		if req.Auth.BearerAuth.DistributionGroups != nil {
			bearerAuth.DistributionGroups = *req.Auth.BearerAuth.DistributionGroups
		}
		s.Auth.BearerAuth = bearerAuth
	}

	return nil
}

func (s *Service) Validate() error {
	if s.Name == "" {
		return errors.New("service name is required")
	}
	if len(s.Name) > 255 {
		return errors.New("service name exceeds maximum length of 255 characters")
	}

	if s.Domain == "" {
		return errors.New("service domain is required")
	}

	if len(s.Targets) == 0 {
		return errors.New("at least one target is required")
	}

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
		if err := validateTargetOptions(i, &target.Options); err != nil {
			return err
		}
	}

	return nil
}

const (
	maxRequestTimeout = 5 * time.Minute
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
	"Content-Length":      {},
	"Content-Type":        {},
	"Cookie":              {},
	"Forwarded":           {},
	"X-Forwarded-For":     {},
	"X-Forwarded-Host":    {},
	"X-Forwarded-Port":    {},
	"X-Forwarded-Proto":   {},
	"X-Real-Ip":           {},
}

func validateTargetOptions(idx int, opts *TargetOptions) error {
	if opts.PathRewrite != "" && opts.PathRewrite != PathRewritePreserve {
		return fmt.Errorf("target %d: unknown path_rewrite mode %q", idx, opts.PathRewrite)
	}

	if opts.RequestTimeout != 0 {
		if opts.RequestTimeout <= 0 {
			return fmt.Errorf("target %d: request_timeout must be positive", idx)
		}
		if opts.RequestTimeout > maxRequestTimeout {
			return fmt.Errorf("target %d: request_timeout exceeds maximum of %s", idx, maxRequestTimeout)
		}
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

func (s *Service) EventMeta() map[string]any {
	return map[string]any{"name": s.Name, "domain": s.Domain, "proxy_cluster": s.ProxyCluster, "source": s.Source, "auth": s.isAuthEnabled()}
}

func (s *Service) isAuthEnabled() bool {
	return s.Auth.PasswordAuth != nil || s.Auth.PinAuth != nil || s.Auth.BearerAuth != nil
}

func (s *Service) Copy() *Service {
	targets := make([]*Target, len(s.Targets))
	for i, target := range s.Targets {
		targetCopy := *target
		if len(target.Options.CustomHeaders) > 0 {
			targetCopy.Options.CustomHeaders = make(map[string]string, len(target.Options.CustomHeaders))
			for k, v := range target.Options.CustomHeaders {
				targetCopy.Options.CustomHeaders[k] = v
			}
		}
		targets[i] = &targetCopy
	}

	return &Service{
		ID:                s.ID,
		AccountID:         s.AccountID,
		Name:              s.Name,
		Domain:            s.Domain,
		ProxyCluster:      s.ProxyCluster,
		Targets:           targets,
		Enabled:           s.Enabled,
		PassHostHeader:    s.PassHostHeader,
		RewriteRedirects:  s.RewriteRedirects,
		Auth:              s.Auth,
		Meta:              s.Meta,
		SessionPrivateKey: s.SessionPrivateKey,
		SessionPublicKey:  s.SessionPublicKey,
		Source:            s.Source,
		SourcePeer:        s.SourcePeer,
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
	Port       int
	Protocol   string
	Domain     string
	Pin        string
	Password   string
	UserGroups []string
}

// Validate checks all fields of the expose request.
func (r *ExposeServiceRequest) Validate() error {
	if r == nil {
		return errors.New("request cannot be nil")
	}

	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", r.Port)
	}

	if r.Protocol != "http" && r.Protocol != "https" {
		return fmt.Errorf("unsupported protocol %q: must be http or https", r.Protocol)
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
	service := &Service{
		AccountID: accountID,
		Name:      serviceName,
		Enabled:   true,
		Targets: []*Target{
			{
				AccountID:  accountID,
				Port:       r.Port,
				Protocol:   r.Protocol,
				TargetId:   peerID,
				TargetType: TargetTypePeer,
				Enabled:    true,
			},
		},
	}

	if r.Domain != "" {
		service.Domain = serviceName + "." + r.Domain
	}

	if r.Pin != "" {
		service.Auth.PinAuth = &PINAuthConfig{
			Enabled: true,
			Pin:     r.Pin,
		}
	}

	if r.Password != "" {
		service.Auth.PasswordAuth = &PasswordAuthConfig{
			Enabled:  true,
			Password: r.Password,
		}
	}

	if len(r.UserGroups) > 0 {
		service.Auth.BearerAuth = &BearerAuthConfig{
			Enabled:            true,
			DistributionGroups: r.UserGroups,
		}
	}

	return service
}

// ExposeServiceResponse contains the result of a successful peer expose creation.
type ExposeServiceResponse struct {
	ServiceName string
	ServiceURL  string
	Domain      string
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
