package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func serviceAuthToAPI(auth AuthConfig) api.ServiceAuthConfig {
	config := api.ServiceAuthConfig{}
	if auth.PasswordAuth != nil {
		config.PasswordAuth = &api.PasswordAuthConfig{Enabled: auth.PasswordAuth.Enabled}
	}
	if auth.PinAuth != nil {
		config.PinAuth = &api.PINAuthConfig{Enabled: auth.PinAuth.Enabled}
	}
	if auth.BearerAuth != nil {
		config.BearerAuth = &api.BearerAuthConfig{
			Enabled:            auth.BearerAuth.Enabled,
			DistributionGroups: &auth.BearerAuth.DistributionGroups,
		}
	}
	if len(auth.HeaderAuths) > 0 {
		headers := make([]api.HeaderAuthConfig, 0, len(auth.HeaderAuths))
		for _, header := range auth.HeaderAuths {
			if header == nil {
				continue
			}
			headers = append(headers, api.HeaderAuthConfig{Enabled: header.Enabled, Header: header.Header})
		}
		config.HeaderAuths = &headers
	}
	return config
}

func serviceTargetsToAPI(targets []*Target, terminated bool) []api.ServiceTarget {
	apiTargets := make([]api.ServiceTarget, 0, len(targets))
	for _, target := range targets {
		converted := api.ServiceTarget{
			Path:       target.Path,
			Host:       &target.Host,
			Port:       int(target.Port),
			Protocol:   api.ServiceTargetProtocol(target.Protocol),
			TargetId:   target.TargetId,
			TargetType: api.ServiceTargetTargetType(target.TargetType),
			Enabled:    target.Enabled && !terminated,
		}
		opts := targetOptionsToAPI(target.Options)
		if opts == nil {
			opts = &api.ServiceTargetOptions{}
		}
		if target.ProxyProtocol {
			opts.ProxyProtocol = &target.ProxyProtocol
		}
		converted.Options = opts
		apiTargets = append(apiTargets, converted)
	}
	return apiTargets
}

func serviceMetaToAPI(meta Meta) api.ServiceMeta {
	converted := api.ServiceMeta{
		CreatedAt: meta.CreatedAt,
		Status:    api.ServiceMetaStatus(meta.Status),
	}
	if meta.CertificateIssuedAt != nil {
		converted.CertificateIssuedAt = meta.CertificateIssuedAt
	}
	return converted
}

func servicePortMappingsToAPI(service *Service) *[]api.ServicePortMapping {
	if !service.IsL4() {
		return nil
	}
	portMappings := service.PortMappings
	if len(portMappings) == 0 {
		ownedService := *service
		ownedService.PopulatePortMappingsFromLegacy()
		portMappings = ownedService.PortMappings
	}
	mappings := make([]api.ServicePortMapping, 0, len(portMappings))
	for _, mapping := range portMappings {
		if mapping == nil {
			continue
		}
		mappings = append(mappings, api.ServicePortMapping{
			Protocol:        api.ServicePortMappingProtocol(mapping.Protocol),
			ListenPortStart: int(mapping.ListenPortStart),
			ListenPortEnd:   int(mapping.ListenPortEnd),
			TargetPortStart: int(mapping.TargetPortStart),
			TargetPortEnd:   int(mapping.TargetPortEnd),
		})
	}
	return &mappings
}

func targetOptionsToAPI(opts TargetOptions) *api.ServiceTargetOptions {
	if !opts.SkipTLSVerify && opts.RequestTimeout == 0 && opts.SessionIdleTimeout == 0 &&
		opts.PathRewrite == "" && len(opts.CustomHeaders) == 0 && !opts.DirectUpstream {
		return nil
	}
	apiOpts := &api.ServiceTargetOptions{}
	if opts.SkipTLSVerify {
		apiOpts.SkipTlsVerify = &opts.SkipTLSVerify
	}
	if opts.RequestTimeout != 0 {
		d := opts.RequestTimeout.String()
		apiOpts.RequestTimeout = &d
	}
	if opts.SessionIdleTimeout != 0 {
		d := opts.SessionIdleTimeout.String()
		apiOpts.SessionIdleTimeout = &d
	}
	if opts.PathRewrite != "" {
		pathRewrite := api.ServiceTargetOptionsPathRewrite(opts.PathRewrite)
		apiOpts.PathRewrite = &pathRewrite
	}
	if len(opts.CustomHeaders) > 0 {
		apiOpts.CustomHeaders = &opts.CustomHeaders
	}
	if opts.DirectUpstream {
		apiOpts.DirectUpstream = &opts.DirectUpstream
	}
	return apiOpts
}

func targetOptionsFromAPI(idx int, options *api.ServiceTargetOptions) (TargetOptions, error) {
	var opts TargetOptions
	if options.SkipTlsVerify != nil {
		opts.SkipTLSVerify = *options.SkipTlsVerify
	}
	if options.RequestTimeout != nil {
		duration, err := time.ParseDuration(*options.RequestTimeout)
		if err != nil {
			return opts, fmt.Errorf("target %d: parse request_timeout %q: %w", idx, *options.RequestTimeout, err)
		}
		opts.RequestTimeout = duration
	}
	if options.SessionIdleTimeout != nil {
		duration, err := time.ParseDuration(*options.SessionIdleTimeout)
		if err != nil {
			return opts, fmt.Errorf("target %d: parse session_idle_timeout %q: %w", idx, *options.SessionIdleTimeout, err)
		}
		opts.SessionIdleTimeout = duration
	}
	if options.PathRewrite != nil {
		opts.PathRewrite = PathRewriteMode(*options.PathRewrite)
	}
	if options.CustomHeaders != nil {
		opts.CustomHeaders = *options.CustomHeaders
	}
	if options.DirectUpstream != nil {
		opts.DirectUpstream = *options.DirectUpstream
	}
	return opts, nil
}

func (s *Service) FromAPIRequest(req *api.ServiceRequest, accountID string) error {
	if err := s.applyAPIRequestFields(req, accountID); err != nil {
		return err
	}

	targets, err := targetsFromAPI(accountID, req.Targets)
	if err != nil {
		return err
	}
	s.Targets = targets
	if err := s.applyAPIPortMappings(req, accountID); err != nil {
		return err
	}
	if err := s.applyAPIRequestOptions(req); err != nil {
		return err
	}
	return s.CanonicalizeDomain()
}

func (s *Service) applyAPIRequestFields(req *api.ServiceRequest, accountID string) error {
	s.Name = req.Name
	s.Domain = req.Domain
	s.AccountID = accountID
	if req.Mode != nil {
		s.Mode = string(*req.Mode)
	}
	if req.ListenPort != nil {
		if *req.ListenPort < 0 || *req.ListenPort > 65535 {
			return fmt.Errorf("listen_port must be between 0 and 65535, got %d", *req.ListenPort)
		}
		s.ListenPort = uint16(*req.ListenPort) //nolint:gosec // bounds checked above
	}
	if req.Private != nil {
		s.Private = *req.Private
	}
	if req.AccessGroups == nil {
		s.AccessGroups = nil
	} else {
		s.AccessGroups = append([]string(nil), *req.AccessGroups...)
	}
	return nil
}

func (s *Service) applyAPIPortMappings(req *api.ServiceRequest, accountID string) error {
	mappings, err := portMappingsFromAPI(accountID, req.PortMappings)
	if err != nil || req.PortMappings == nil {
		return err
	}
	s.PortMappingsSet = true
	s.PortMappings = mappings
	if len(mappings) == 0 {
		return errors.New("port_mappings must contain at least one mapping")
	}
	first := mappings[0]
	if err := s.validateAPILegacyMapping(req, first); err != nil {
		return err
	}
	if err := s.validateAPIMappingTarget(first); err != nil {
		return err
	}
	s.syncLegacyFields()
	return nil
}

func (s *Service) validateAPILegacyMapping(req *api.ServiceRequest, first *PortMapping) error {
	if req.Mode != nil && s.Mode != first.Protocol {
		return fmt.Errorf("mode %q must match port_mappings[0].protocol %q", s.Mode, first.Protocol)
	}
	if req.ListenPort != nil && s.ListenPort != first.ListenPortStart {
		return fmt.Errorf("listen_port %d must match port_mappings[0].listen_port_start %d", s.ListenPort, first.ListenPortStart)
	}
	return nil
}

func (s *Service) validateAPIMappingTarget(first *PortMapping) error {
	if len(s.Targets) != 1 {
		return nil
	}
	target := s.Targets[0]
	if target.Port != 0 && target.Port != first.TargetPortStart {
		return fmt.Errorf("targets[0].port %d must match port_mappings[0].target_port_start %d", target.Port, first.TargetPortStart)
	}
	expectedProtocol := targetProtocolForMapping(first.Protocol)
	if target.Protocol != "" && target.Protocol != expectedProtocol {
		return fmt.Errorf("targets[0].protocol %q must be %q for port_mappings[0].protocol %q", target.Protocol, expectedProtocol, first.Protocol)
	}
	return nil
}

func (s *Service) applyAPIRequestOptions(req *api.ServiceRequest) error {
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
	if req.AccessRestrictions == nil {
		return nil
	}
	restrictions, err := restrictionsFromAPI(req.AccessRestrictions)
	if err != nil {
		return err
	}
	s.Restrictions = restrictions
	return nil
}

func targetsFromAPI(accountID string, apiTargetsPtr *[]api.ServiceTarget) ([]*Target, error) {
	var apiTargets []api.ServiceTarget
	if apiTargetsPtr != nil {
		apiTargets = *apiTargetsPtr
	}

	targets := make([]*Target, 0, len(apiTargets))
	for i, apiTarget := range apiTargets {
		if apiTarget.Port < 0 || apiTarget.Port > 65535 {
			return nil, fmt.Errorf("target %d: port must be between 0 and 65535, got %d", i, apiTarget.Port)
		}
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

func portMappingsFromAPI(accountID string, apiMappingsPtr *[]api.ServicePortMapping) ([]*PortMapping, error) {
	if apiMappingsPtr == nil {
		return nil, nil
	}

	mappings := make([]*PortMapping, 0, len(*apiMappingsPtr))
	for i, apiMapping := range *apiMappingsPtr {
		values := []struct {
			name  string
			value int
		}{
			{name: "listen_port_start", value: apiMapping.ListenPortStart},
			{name: "listen_port_end", value: apiMapping.ListenPortEnd},
			{name: "target_port_start", value: apiMapping.TargetPortStart},
			{name: "target_port_end", value: apiMapping.TargetPortEnd},
		}
		for _, value := range values {
			if value.value < 1 || value.value > 65535 {
				return nil, fmt.Errorf("port_mappings[%d].%s must be between 1 and 65535, got %d", i, value.name, value.value)
			}
		}

		mappings = append(mappings, &PortMapping{
			AccountID:       accountID,
			Protocol:        string(apiMapping.Protocol),
			ListenPortStart: uint16(apiMapping.ListenPortStart), //nolint:gosec // bounds checked above
			ListenPortEnd:   uint16(apiMapping.ListenPortEnd),   //nolint:gosec // bounds checked above
			TargetPortStart: uint16(apiMapping.TargetPortStart), //nolint:gosec // bounds checked above
			TargetPortEnd:   uint16(apiMapping.TargetPortEnd),   //nolint:gosec // bounds checked above
			Position:        i,
		})
	}
	return mappings, nil
}

func authFromAPI(reqAuth *api.ServiceAuthConfig) AuthConfig {
	var auth AuthConfig
	if reqAuth.PasswordAuth != nil {
		auth.PasswordAuth = &PasswordAuthConfig{Enabled: reqAuth.PasswordAuth.Enabled, Password: reqAuth.PasswordAuth.Password}
	}
	if reqAuth.PinAuth != nil {
		auth.PinAuth = &PINAuthConfig{Enabled: reqAuth.PinAuth.Enabled, Pin: reqAuth.PinAuth.Pin}
	}
	if reqAuth.BearerAuth != nil {
		bearerAuth := &BearerAuthConfig{Enabled: reqAuth.BearerAuth.Enabled}
		if reqAuth.BearerAuth.DistributionGroups != nil {
			bearerAuth.DistributionGroups = *reqAuth.BearerAuth.DistributionGroups
		}
		auth.BearerAuth = bearerAuth
	}
	if reqAuth.HeaderAuths != nil {
		for _, header := range *reqAuth.HeaderAuths {
			auth.HeaderAuths = append(auth.HeaderAuths, &HeaderAuthConfig{
				Enabled: header.Enabled,
				Header:  header.Header,
				Value:   header.Value,
			})
		}
	}
	return auth
}

func restrictionsFromAPI(restrictions *api.AccessRestrictions) (AccessRestrictions, error) {
	if restrictions == nil {
		return AccessRestrictions{}, nil
	}
	var result AccessRestrictions
	if restrictions.AllowedCidrs != nil {
		result.AllowedCIDRs = *restrictions.AllowedCidrs
	}
	if restrictions.BlockedCidrs != nil {
		result.BlockedCIDRs = *restrictions.BlockedCidrs
	}
	if restrictions.AllowedCountries != nil {
		result.AllowedCountries = *restrictions.AllowedCountries
	}
	if restrictions.BlockedCountries != nil {
		result.BlockedCountries = *restrictions.BlockedCountries
	}
	if restrictions.CrowdsecMode != nil {
		if !restrictions.CrowdsecMode.Valid() {
			return AccessRestrictions{}, fmt.Errorf("invalid crowdsec_mode %q", *restrictions.CrowdsecMode)
		}
		result.CrowdSecMode = string(*restrictions.CrowdsecMode)
	}
	return result, nil
}

func restrictionsToAPI(restrictions AccessRestrictions) *api.AccessRestrictions {
	if len(restrictions.AllowedCIDRs) == 0 && len(restrictions.BlockedCIDRs) == 0 &&
		len(restrictions.AllowedCountries) == 0 && len(restrictions.BlockedCountries) == 0 &&
		restrictions.CrowdSecMode == "" {
		return nil
	}
	result := &api.AccessRestrictions{}
	if len(restrictions.AllowedCIDRs) > 0 {
		result.AllowedCidrs = &restrictions.AllowedCIDRs
	}
	if len(restrictions.BlockedCIDRs) > 0 {
		result.BlockedCidrs = &restrictions.BlockedCIDRs
	}
	if len(restrictions.AllowedCountries) > 0 {
		result.AllowedCountries = &restrictions.AllowedCountries
	}
	if len(restrictions.BlockedCountries) > 0 {
		result.BlockedCountries = &restrictions.BlockedCountries
	}
	if restrictions.CrowdSecMode != "" {
		mode := api.AccessRestrictionsCrowdsecMode(restrictions.CrowdSecMode)
		result.CrowdsecMode = &mode
	}
	return result
}
