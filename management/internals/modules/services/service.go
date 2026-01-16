package services

import (
	"errors"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

type Target struct {
	Path    string `json:"path"`
	Host    string `json:"host"`
	Enabled bool   `json:"enabled"`
}

type Service struct {
	ID                 string `gorm:"primaryKey"`
	AccountID          string `gorm:"index"`
	Name               string
	Description        string
	Domain             string   `gorm:"index"`
	Targets            []Target `gorm:"serializer:json"`
	DistributionGroups []string `gorm:"serializer:json"`
	Enabled            bool
	Exposed            bool

	// Authentication configuration
	AuthType          string
	AuthBasicUsername string
	AuthBasicPassword string
	AuthPINValue      string
	AuthPINHeader     string
	AuthBearerEnabled bool
}

func NewService(accountID, name, description, domain string, targets []Target, distributionGroups []string, enabled, exposed bool) *Service {
	return &Service{
		ID:                 xid.New().String(),
		AccountID:          accountID,
		Name:               name,
		Description:        description,
		Domain:             domain,
		Targets:            targets,
		DistributionGroups: distributionGroups,
		Enabled:            enabled,
		Exposed:            exposed,
	}
}

func (s *Service) ToAPIResponse() *api.Service {
	var authConfig *api.ServiceAuthConfig

	switch s.AuthType {
	case "basic":
		authConfig = &api.ServiceAuthConfig{
			Type: "basic",
			BasicAuth: &api.BasicAuthConfig{
				Username: s.AuthBasicUsername,
				Password: s.AuthBasicPassword,
			},
		}
	case "pin":
		authConfig = &api.ServiceAuthConfig{
			Type: "pin",
			PinAuth: &api.PINAuthConfig{
				Pin:    s.AuthPINValue,
				Header: s.AuthPINHeader,
			},
		}
	case "bearer":
		authConfig = &api.ServiceAuthConfig{
			Type: "bearer",
			BearerAuth: &api.BearerAuthConfig{
				Enabled: s.AuthBearerEnabled,
			},
		}
	}

	// Convert internal targets to API targets
	apiTargets := make([]api.ServiceTarget, 0, len(s.Targets))
	for _, target := range s.Targets {
		apiTargets = append(apiTargets, api.ServiceTarget{
			Path:    target.Path,
			Host:    target.Host,
			Enabled: target.Enabled,
		})
	}

	return &api.Service{
		Id:                 s.ID,
		Name:               s.Name,
		Description:        &s.Description,
		Domain:             s.Domain,
		Targets:            apiTargets,
		DistributionGroups: s.DistributionGroups,
		Enabled:            s.Enabled,
		Exposed:            s.Exposed,
		Auth:               authConfig,
	}
}

func (s *Service) FromAPIRequest(req *api.ServiceRequest) {
	s.Name = req.Name
	s.Domain = req.Domain

	// Convert API targets to internal targets
	targets := make([]Target, 0, len(req.Targets))
	for _, apiTarget := range req.Targets {
		targets = append(targets, Target{
			Path:    apiTarget.Path,
			Host:    apiTarget.Host,
			Enabled: apiTarget.Enabled,
		})
	}
	s.Targets = targets

	s.DistributionGroups = req.DistributionGroups

	if req.Description != nil {
		s.Description = *req.Description
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	s.Enabled = enabled

	exposed := false
	if req.Exposed != nil {
		exposed = *req.Exposed
	}
	s.Exposed = exposed

	// Handle auth config
	if req.Auth != nil {
		s.AuthType = string(req.Auth.Type)

		switch req.Auth.Type {
		case "basic":
			if req.Auth.BasicAuth != nil {
				s.AuthBasicUsername = req.Auth.BasicAuth.Username
				s.AuthBasicPassword = req.Auth.BasicAuth.Password
			}
		case "pin":
			if req.Auth.PinAuth != nil {
				s.AuthPINValue = req.Auth.PinAuth.Pin
				s.AuthPINHeader = req.Auth.PinAuth.Header
			}
		case "bearer":
			if req.Auth.BearerAuth != nil {
				s.AuthBearerEnabled = req.Auth.BearerAuth.Enabled
			}
		}
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

	if len(s.DistributionGroups) == 0 {
		return errors.New("at least one distribution group is required")
	}

	return nil
}

func (s *Service) EventMeta() map[string]any {
	return map[string]any{"name": s.Name, "domain": s.Domain}
}
