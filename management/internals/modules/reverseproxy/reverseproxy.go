package reverseproxy

import (
	"errors"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

type Target struct {
	Path       *string `json:"path,omitempty"`
	Host       string  `json:"host"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	TargetId   string  `json:"target_id"`
	TargetType string  `json:"target_type"`
	Enabled    bool    `json:"enabled"`
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

type LinkAuthConfig struct {
	Enabled bool `json:"enabled"`
}

type AuthConfig struct {
	PasswordAuth *PasswordAuthConfig `json:"password_auth,omitempty" gorm:"serializer:json"`
	PinAuth      *PINAuthConfig      `json:"pin_auth,omitempty" gorm:"serializer:json"`
	BearerAuth   *BearerAuthConfig   `json:"bearer_auth,omitempty" gorm:"serializer:json"`
	LinkAuth     *LinkAuthConfig     `json:"link_auth,omitempty" gorm:"serializer:json"`
}

type ReverseProxy struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	Name      string
	Domain    string   `gorm:"index"`
	Targets   []Target `gorm:"serializer:json"`
	Enabled   bool
	Auth      AuthConfig `gorm:"serializer:json"`
}

func NewReverseProxy(accountID, name, domain string, targets []Target, enabled bool) *ReverseProxy {
	return &ReverseProxy{
		ID:        xid.New().String(),
		AccountID: accountID,
		Name:      name,
		Domain:    domain,
		Targets:   targets,
		Enabled:   enabled,
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

	if r.Auth.LinkAuth != nil {
		authConfig.LinkAuth = &api.LinkAuthConfig{
			Enabled: r.Auth.LinkAuth.Enabled,
		}
	}

	// Convert internal targets to API targets
	apiTargets := make([]api.ReverseProxyTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		apiTargets = append(apiTargets, api.ReverseProxyTarget{
			Path:       target.Path,
			Host:       target.Host,
			Port:       target.Port,
			Protocol:   api.ReverseProxyTargetProtocol(target.Protocol),
			TargetId:   target.TargetId,
			TargetType: api.ReverseProxyTargetTargetType(target.TargetType),
			Enabled:    target.Enabled,
		})
	}

	return &api.ReverseProxy{
		Id:      r.ID,
		Name:    r.Name,
		Domain:  r.Domain,
		Targets: apiTargets,
		Enabled: r.Enabled,
		Auth:    authConfig,
	}
}

func (r *ReverseProxy) FromAPIRequest(req *api.ReverseProxyRequest) {
	r.Name = req.Name
	r.Domain = req.Domain

	// Convert API targets to internal targets
	targets := make([]Target, 0, len(req.Targets))
	for _, apiTarget := range req.Targets {
		targets = append(targets, Target{
			Path:       apiTarget.Path,
			Host:       apiTarget.Host,
			Port:       apiTarget.Port,
			Protocol:   string(apiTarget.Protocol),
			TargetId:   apiTarget.TargetId,
			TargetType: string(apiTarget.TargetType),
			Enabled:    apiTarget.Enabled,
		})
	}
	r.Targets = targets

	r.Enabled = req.Enabled

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

	if req.Auth.LinkAuth != nil {
		r.Auth.LinkAuth = &LinkAuthConfig{
			Enabled: req.Auth.LinkAuth.Enabled,
		}
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

	return nil
}

func (r *ReverseProxy) EventMeta() map[string]any {
	return map[string]any{"name": r.Name, "domain": r.Domain}
}
