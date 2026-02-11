package reverseproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

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

type ProxyStatus string

const (
	StatusPending            ProxyStatus = "pending"
	StatusActive             ProxyStatus = "active"
	StatusTunnelNotCreated   ProxyStatus = "tunnel_not_created"
	StatusCertificatePending ProxyStatus = "certificate_pending"
	StatusCertificateFailed  ProxyStatus = "certificate_failed"
	StatusError              ProxyStatus = "error"

	TargetTypePeer   = "peer"
	TargetTypeHost   = "host"
	TargetTypeDomain = "domain"
	TargetTypeSubnet = "subnet"
)

type Target struct {
	ID         uint    `gorm:"primaryKey" json:"-"`
	AccountID  string  `gorm:"index:idx_target_account;not null" json:"-"`
	ServiceID  string  `gorm:"index:idx_service_targets;not null" json:"-"`
	Path       *string `json:"path,omitempty"`
	Host       string  `json:"host"` // the Host field is only used for subnet targets, otherwise ignored
	Port       int     `gorm:"index:idx_target_port" json:"port"`
	Protocol   string  `gorm:"index:idx_target_protocol" json:"protocol"`
	TargetId   string  `gorm:"index:idx_target_id" json:"target_id"`
	TargetType string  `gorm:"index:idx_target_type" json:"target_type"`
	Enabled    bool    `gorm:"index:idx_target_enabled" json:"enabled"`
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

type OIDCValidationConfig struct {
	Issuer             string
	Audiences          []string
	KeysLocation       string
	MaxTokenAgeSeconds int64
}

type ServiceMeta struct {
	CreatedAt           time.Time
	CertificateIssuedAt time.Time
	Status              string
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
	Auth              AuthConfig  `gorm:"serializer:json"`
	Meta              ServiceMeta `gorm:"embedded;embeddedPrefix:meta_"`
	SessionPrivateKey string      `gorm:"column:session_private_key"`
	SessionPublicKey  string      `gorm:"column:session_public_key"`
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
	s.Meta = ServiceMeta{
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
		apiTargets = append(apiTargets, api.ServiceTarget{
			Path:       target.Path,
			Host:       &target.Host,
			Port:       target.Port,
			Protocol:   api.ServiceTargetProtocol(target.Protocol),
			TargetId:   target.TargetId,
			TargetType: api.ServiceTargetTargetType(target.TargetType),
			Enabled:    target.Enabled,
		})
	}

	meta := api.ServiceMeta{
		CreatedAt: s.Meta.CreatedAt,
		Status:    api.ServiceMetaStatus(s.Meta.Status),
	}

	if !s.Meta.CertificateIssuedAt.IsZero() {
		meta.CertificateIssuedAt = &s.Meta.CertificateIssuedAt
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

func (s *Service) ToProtoMapping(operation Operation, authToken string, oidcConfig OIDCValidationConfig) *proto.ProxyMapping {
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
		pathMappings = append(pathMappings, &proto.PathMapping{
			Path:   path,
			Target: targetURL.String(),
		})
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

func (s *Service) FromAPIRequest(req *api.ServiceRequest, accountID string) {
	s.Name = req.Name
	s.Domain = req.Domain
	s.AccountID = accountID

	targets := make([]*Target, 0, len(req.Targets))
	for _, apiTarget := range req.Targets {
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
	}

	return nil
}

func (s *Service) EventMeta() map[string]any {
	return map[string]any{"name": s.Name, "domain": s.Domain, "proxy_cluster": s.ProxyCluster}
}

func (s *Service) Copy() *Service {
	targets := make([]*Target, len(s.Targets))
	for i, target := range s.Targets {
		targetCopy := *target
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
