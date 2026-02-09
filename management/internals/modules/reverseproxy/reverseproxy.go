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
	Path       *string `json:"path,omitempty"`
	Host       string  `json:"host"` // the Host field is only used for subnet targets, otherwise ignored
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	TargetId   string  `json:"target_id"`
	TargetType string  `json:"target_type"`
	Enabled    bool    `json:"enabled"`
	// AccessLocal indicates the resource is served locally on the router peer,
	// requiring additional peer-level firewall rules for the proxy to access the router directly.
	AccessLocal bool `json:"access_local"`
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

type OIDCValidationConfig struct {
	Issuer             string
	Audiences          []string
	KeysLocation       string
	MaxTokenAgeSeconds int64
}

type ReverseProxyMeta struct {
	CreatedAt           time.Time
	CertificateIssuedAt time.Time
	Status              string
}

type ReverseProxy struct {
	ID                string `gorm:"primaryKey"`
	AccountID         string `gorm:"index"`
	Name              string
	Domain            string    `gorm:"index"`
	ProxyCluster      string    `gorm:"index"`
	Targets           []*Target `gorm:"serializer:json"`
	Enabled           bool
	PassHostHeader    bool
	RewriteRedirects  bool
	Auth              AuthConfig       `gorm:"serializer:json"`
	Meta              ReverseProxyMeta `gorm:"embedded;embeddedPrefix:meta_"`
	SessionPrivateKey string           `gorm:"column:session_private_key"`
	SessionPublicKey  string           `gorm:"column:session_public_key"`
}

func NewReverseProxy(accountID, name, domain, proxyCluster string, targets []*Target, enabled bool) *ReverseProxy {
	rp := &ReverseProxy{
		AccountID:    accountID,
		Name:         name,
		Domain:       domain,
		ProxyCluster: proxyCluster,
		Targets:      targets,
		Enabled:      enabled,
	}
	rp.InitNewRecord()
	return rp
}

// InitNewRecord generates a new unique ID and resets metadata for a newly created
// ReverseProxy record. This overwrites any existing ID and Meta fields and should
// only be called during initial creation, not for updates.
func (r *ReverseProxy) InitNewRecord() {
	r.ID = xid.New().String()
	r.Meta = ReverseProxyMeta{
		CreatedAt: time.Now(),
		Status:    string(StatusPending),
	}
}

func (r *ReverseProxy) ToAPIResponse() *api.ReverseProxy {
	authConfig := api.ReverseProxyAuthConfig{}

	if r.Auth.PasswordAuth != nil {
		authConfig.PasswordAuth = &api.PasswordAuthConfig{
			Enabled:  r.Auth.PasswordAuth.Enabled,
			Password: r.Auth.PasswordAuth.Password,
		}
	}

	if r.Auth.PinAuth != nil {
		authConfig.PinAuth = &api.PINAuthConfig{
			Enabled: r.Auth.PinAuth.Enabled,
			Pin:     r.Auth.PinAuth.Pin,
		}
	}

	if r.Auth.BearerAuth != nil {
		authConfig.BearerAuth = &api.BearerAuthConfig{
			Enabled:            r.Auth.BearerAuth.Enabled,
			DistributionGroups: &r.Auth.BearerAuth.DistributionGroups,
		}
	}

	// Convert internal targets to API targets
	apiTargets := make([]api.ReverseProxyTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		apiTargets = append(apiTargets, api.ReverseProxyTarget{
			Path:        target.Path,
			Host:        &target.Host,
			Port:        target.Port,
			Protocol:    api.ReverseProxyTargetProtocol(target.Protocol),
			TargetId:    target.TargetId,
			TargetType:  api.ReverseProxyTargetTargetType(target.TargetType),
			Enabled:     target.Enabled,
			AccessLocal: &target.AccessLocal,
		})
	}

	meta := api.ReverseProxyMeta{
		CreatedAt: r.Meta.CreatedAt,
		Status:    api.ReverseProxyMetaStatus(r.Meta.Status),
	}

	if !r.Meta.CertificateIssuedAt.IsZero() {
		meta.CertificateIssuedAt = &r.Meta.CertificateIssuedAt
	}

	resp := &api.ReverseProxy{
		Id:               r.ID,
		Name:             r.Name,
		Domain:           r.Domain,
		Targets:          apiTargets,
		Enabled:          r.Enabled,
		PassHostHeader:   &r.PassHostHeader,
		RewriteRedirects: &r.RewriteRedirects,
		Auth:             authConfig,
		Meta:             meta,
	}

	if r.ProxyCluster != "" {
		resp.ProxyCluster = &r.ProxyCluster
	}

	return resp
}

func (r *ReverseProxy) ToProtoMapping(operation Operation, authToken string, oidcConfig OIDCValidationConfig) *proto.ProxyMapping {
	pathMappings := make([]*proto.PathMapping, 0, len(r.Targets))
	for _, target := range r.Targets {
		if !target.Enabled {
			continue
		}

		path := "/"
		if target.Path != nil {
			path = *target.Path
		}

		// TODO: Make path prefix stripping configurable per-target.
		// Currently the matching prefix is baked into the target URL path,
		// so the proxy strips-then-re-adds it (effectively a no-op).
		targetURL := url.URL{
			Scheme: target.Protocol,
			Host:   target.Host,
			Path:   path,
		}
		if target.Port > 0 && !isDefaultPort(target.Protocol, target.Port) {
			targetURL.Host = net.JoinHostPort(targetURL.Host, strconv.Itoa(target.Port))
		}

		pathMappings = append(pathMappings, &proto.PathMapping{
			Path:   path,
			Target: targetURL.String(),
		})
	}

	auth := &proto.Authentication{
		SessionKey:           r.SessionPublicKey,
		MaxSessionAgeSeconds: int64((time.Hour * 24).Seconds()),
	}

	if r.Auth.PasswordAuth != nil && r.Auth.PasswordAuth.Enabled {
		auth.Password = true
	}

	if r.Auth.PinAuth != nil && r.Auth.PinAuth.Enabled {
		auth.Pin = true
	}

	if r.Auth.BearerAuth != nil && r.Auth.BearerAuth.Enabled {
		auth.Oidc = true
	}

	return &proto.ProxyMapping{
		Type:             operationToProtoType(operation),
		Id:               r.ID,
		Domain:           r.Domain,
		Path:             pathMappings,
		AuthToken:        authToken,
		Auth:             auth,
		AccountId:        r.AccountID,
		PassHostHeader:   r.PassHostHeader,
		RewriteRedirects: r.RewriteRedirects,
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

func (r *ReverseProxy) FromAPIRequest(req *api.ReverseProxyRequest, accountID string) {
	r.Name = req.Name
	r.Domain = req.Domain
	r.AccountID = accountID

	targets := make([]*Target, 0, len(req.Targets))
	for _, apiTarget := range req.Targets {
		accessLocal := apiTarget.AccessLocal != nil && *apiTarget.AccessLocal
		target := &Target{
			Path:        apiTarget.Path,
			Port:        apiTarget.Port,
			Protocol:    string(apiTarget.Protocol),
			TargetId:    apiTarget.TargetId,
			TargetType:  string(apiTarget.TargetType),
			Enabled:     apiTarget.Enabled,
			AccessLocal: accessLocal,
		}
		if apiTarget.Host != nil {
			target.Host = *apiTarget.Host
		}
		targets = append(targets, target)
	}
	r.Targets = targets

	r.Enabled = req.Enabled

	if req.PassHostHeader != nil {
		r.PassHostHeader = *req.PassHostHeader
	}

	if req.RewriteRedirects != nil {
		r.RewriteRedirects = *req.RewriteRedirects
	}

	if req.Auth.PasswordAuth != nil {
		r.Auth.PasswordAuth = &PasswordAuthConfig{
			Enabled:  req.Auth.PasswordAuth.Enabled,
			Password: req.Auth.PasswordAuth.Password,
		}
	}

	if req.Auth.PinAuth != nil {
		r.Auth.PinAuth = &PINAuthConfig{
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
		r.Auth.BearerAuth = bearerAuth
	}
}

func (r *ReverseProxy) Validate() error {
	if r.Name == "" {
		return errors.New("reverse proxy name is required")
	}
	if len(r.Name) > 255 {
		return errors.New("reverse proxy name exceeds maximum length of 255 characters")
	}

	if r.Domain == "" {
		return errors.New("reverse proxy domain is required")
	}

	if len(r.Targets) == 0 {
		return errors.New("at least one target is required")
	}

	for i, target := range r.Targets {
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

func (r *ReverseProxy) EventMeta() map[string]any {
	return map[string]any{"name": r.Name, "domain": r.Domain, "proxy_cluster": r.ProxyCluster}
}

func (r *ReverseProxy) Copy() *ReverseProxy {
	targets := make([]*Target, len(r.Targets))
	copy(targets, r.Targets)

	return &ReverseProxy{
		ID:                r.ID,
		AccountID:         r.AccountID,
		Name:              r.Name,
		Domain:            r.Domain,
		ProxyCluster:      r.ProxyCluster,
		Targets:           targets,
		Enabled:           r.Enabled,
		PassHostHeader:    r.PassHostHeader,
		RewriteRedirects:  r.RewriteRedirects,
		Auth:              r.Auth,
		Meta:              r.Meta,
		SessionPrivateKey: r.SessionPrivateKey,
		SessionPublicKey:  r.SessionPublicKey,
	}
}

func (r *ReverseProxy) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	if r.SessionPrivateKey != "" {
		var err error
		r.SessionPrivateKey, err = enc.Encrypt(r.SessionPrivateKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *ReverseProxy) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	if r.SessionPrivateKey != "" {
		var err error
		r.SessionPrivateKey, err = enc.Decrypt(r.SessionPrivateKey)
		if err != nil {
			return err
		}
	}

	return nil
}
