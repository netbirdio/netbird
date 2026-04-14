package device_auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// ─── Response types ────────────────────────────────────────────────────────────

// caConfigResponse is the response body for GET|PUT /device-auth/ca/config.
// Sensitive credential fields are always returned as empty strings; their
// presence is indicated by the corresponding has_* boolean field.
type caConfigResponse struct {
	CAType    string            `json:"ca_type"`
	Vault     *vaultConfigResp  `json:"vault,omitempty"`
	Smallstep *smallstepCfgResp `json:"smallstep,omitempty"`
	SCEP      *scepConfigResp   `json:"scep,omitempty"`
}

type vaultConfigResp struct {
	Address        string `json:"address"`
	Token          string `json:"token"`    // always empty in responses
	HasToken       bool   `json:"has_token"` // true when a token is stored
	Mount          string `json:"mount"`
	Role           string `json:"role"`
	Namespace      string `json:"namespace"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type smallstepCfgResp struct {
	URL                 string `json:"url"`
	ProvisionerToken    string `json:"provisioner_token"`     // always empty in responses
	HasProvisionerToken bool   `json:"has_provisioner_token"` // true when a token is stored
	Fingerprint         string `json:"fingerprint"`
	TimeoutSeconds      int    `json:"timeout_seconds"`
}

type scepConfigResp struct {
	URL            string `json:"url"`
	Challenge      string `json:"challenge"`     // always empty in responses
	HasChallenge   bool   `json:"has_challenge"` // true when a challenge is stored
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// ─── Request types ─────────────────────────────────────────────────────────────

// caConfigRequest is the request body for PUT /device-auth/ca/config.
type caConfigRequest struct {
	CAType    string           `json:"ca_type"`
	Vault     *vaultCfgReq     `json:"vault,omitempty"`
	Smallstep *smallstepCfgReq `json:"smallstep,omitempty"`
	SCEP      *scepCfgReq      `json:"scep,omitempty"`
}

type vaultCfgReq struct {
	Address        string `json:"address"`
	Token          string `json:"token"`    // empty means "preserve existing"
	Mount          string `json:"mount"`
	Role           string `json:"role"`
	Namespace      string `json:"namespace"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type smallstepCfgReq struct {
	URL                 string `json:"url"`
	ProvisionerToken    string `json:"provisioner_token"`  // empty means "preserve existing"
	Fingerprint         string `json:"fingerprint"`
	TimeoutSeconds      int    `json:"timeout_seconds"`
}

type scepCfgReq struct {
	URL            string `json:"url"`
	Challenge      string `json:"challenge"`   // empty means "preserve existing"
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// getCAConfig returns the CA-specific configuration for the account.
// Credential fields (token, provisioner_token, challenge) are always redacted;
// their presence is indicated by the corresponding has_* boolean field.
func (h *handler) getCAConfig(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	accountSettings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp, err := buildCAConfigResponse(accountSettings.DeviceAuth)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

// putCAConfig replaces the CA-specific configuration for the account.
// When a credential field (token, provisioner_token, challenge) is sent as an
// empty string, the existing stored credential is preserved unchanged.
func (h *handler) putCAConfig(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	var req caConfigRequest
	// Limit body to 1 MiB to prevent memory exhaustion from oversized payloads.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	// Validate ca_type enum before touching the store.
	validCATypes := map[string]bool{
		types.DeviceAuthCATypeBuiltin:   true,
		types.DeviceAuthCATypeVault:     true,
		types.DeviceAuthCATypeSmallstep: true,
		types.DeviceAuthCATypeSCEP:      true,
	}
	if req.CAType != "" && !validCATypes[req.CAType] {
		util.WriteErrorResponse("invalid ca_type: must be one of 'builtin', 'vault', 'smallstep', 'scep'", http.StatusBadRequest, w)
		return
	}

	// Use LockingStrengthUpdate to serialize concurrent CA config updates.
	accountSettings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if accountSettings.DeviceAuth == nil {
		accountSettings.DeviceAuth = &types.DeviceAuthSettings{}
	}

	if err := applyCAConfigRequest(accountSettings.DeviceAuth, req); err != nil {
		util.WriteErrorResponse("invalid CA config: "+err.Error(), http.StatusBadRequest, w)
		return
	}

	if err := h.store.SaveAccountSettings(r.Context(), userAuth.AccountId, accountSettings); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp, err := buildCAConfigResponse(accountSettings.DeviceAuth)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// buildCAConfigResponse constructs a redacted caConfigResponse from DeviceAuthSettings.
// Credential fields are replaced with empty strings; has_* booleans indicate presence.
func buildCAConfigResponse(s *types.DeviceAuthSettings) (*caConfigResponse, error) {
	if s == nil {
		return &caConfigResponse{CAType: types.DeviceAuthCATypeBuiltin}, nil
	}

	caType := s.CAType
	if caType == "" {
		caType = types.DeviceAuthCATypeBuiltin
	}

	resp := &caConfigResponse{CAType: caType}

	switch caType {
	case types.DeviceAuthCATypeVault:
		var cfg struct {
			Address        string `json:"address"`
			Token          string `json:"token"`
			Mount          string `json:"mount"`
			Role           string `json:"role"`
			Namespace      string `json:"namespace"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if s.CAConfig != "" {
			if err := json.Unmarshal([]byte(s.CAConfig), &cfg); err != nil {
				return nil, err
			}
		}
		resp.Vault = &vaultConfigResp{
			Address:        cfg.Address,
			Token:          "",
			HasToken:       cfg.Token != "",
			Mount:          cfg.Mount,
			Role:           cfg.Role,
			Namespace:      cfg.Namespace,
			TimeoutSeconds: cfg.TimeoutSeconds,
		}

	case types.DeviceAuthCATypeSmallstep:
		var cfg struct {
			URL              string `json:"url"`
			ProvisionerToken string `json:"provisioner_token"`
			Fingerprint      string `json:"fingerprint"`
			TimeoutSeconds   int    `json:"timeout_seconds"`
		}
		if s.CAConfig != "" {
			if err := json.Unmarshal([]byte(s.CAConfig), &cfg); err != nil {
				return nil, err
			}
		}
		resp.Smallstep = &smallstepCfgResp{
			URL:                 cfg.URL,
			ProvisionerToken:    "",
			HasProvisionerToken: cfg.ProvisionerToken != "",
			Fingerprint:         cfg.Fingerprint,
			TimeoutSeconds:      cfg.TimeoutSeconds,
		}

	case types.DeviceAuthCATypeSCEP:
		var cfg struct {
			URL            string `json:"url"`
			Challenge      string `json:"challenge"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if s.CAConfig != "" {
			if err := json.Unmarshal([]byte(s.CAConfig), &cfg); err != nil {
				return nil, err
			}
		}
		resp.SCEP = &scepConfigResp{
			URL:            cfg.URL,
			Challenge:      "",
			HasChallenge:   cfg.Challenge != "",
			TimeoutSeconds: cfg.TimeoutSeconds,
		}
	}

	return resp, nil
}

// applyCAConfigRequest merges the request into s.DeviceAuthSettings.
// When a credential field (token, provisioner_token, challenge) is empty in the
// request, the existing stored value is preserved.
// Returns an error if a sub-object for a different CA type than s.CAType is provided.
func applyCAConfigRequest(s *types.DeviceAuthSettings, req caConfigRequest) error {
	if req.CAType != "" {
		s.CAType = req.CAType
	}

	// Reject mismatched sub-objects to prevent silent misconfiguration.
	if s.CAType != types.DeviceAuthCATypeVault && req.Vault != nil {
		return fmt.Errorf("ca_type is %q but vault sub-object was provided", s.CAType)
	}
	if s.CAType != types.DeviceAuthCATypeSmallstep && req.Smallstep != nil {
		return fmt.Errorf("ca_type is %q but smallstep sub-object was provided", s.CAType)
	}
	if s.CAType != types.DeviceAuthCATypeSCEP && req.SCEP != nil {
		return fmt.Errorf("ca_type is %q but scep sub-object was provided", s.CAType)
	}

	switch s.CAType {
	case types.DeviceAuthCATypeVault:
		if req.Vault == nil {
			return nil
		}
		// Read existing config to preserve credentials when not re-supplied.
		var existing struct {
			Address        string `json:"address"`
			Token          string `json:"token"`
			Mount          string `json:"mount"`
			Role           string `json:"role"`
			Namespace      string `json:"namespace"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if s.CAConfig != "" {
			if err := json.Unmarshal([]byte(s.CAConfig), &existing); err != nil {
				return err
			}
		}

		// Apply incoming fields; preserve credential when empty string is sent.
		existing.Address = req.Vault.Address
		existing.Mount = req.Vault.Mount
		existing.Role = req.Vault.Role
		existing.Namespace = req.Vault.Namespace
		existing.TimeoutSeconds = req.Vault.TimeoutSeconds
		if req.Vault.Token != "" {
			existing.Token = req.Vault.Token
		}

		raw, err := json.Marshal(existing)
		if err != nil {
			return err
		}
		s.CAConfig = string(raw)

	case types.DeviceAuthCATypeSmallstep:
		if req.Smallstep == nil {
			return nil
		}
		var existing struct {
			URL              string `json:"url"`
			ProvisionerToken string `json:"provisioner_token"`
			Fingerprint      string `json:"fingerprint"`
			TimeoutSeconds   int    `json:"timeout_seconds"`
		}
		if s.CAConfig != "" {
			if err := json.Unmarshal([]byte(s.CAConfig), &existing); err != nil {
				return err
			}
		}

		existing.URL = req.Smallstep.URL
		existing.Fingerprint = req.Smallstep.Fingerprint
		existing.TimeoutSeconds = req.Smallstep.TimeoutSeconds
		if req.Smallstep.ProvisionerToken != "" {
			existing.ProvisionerToken = req.Smallstep.ProvisionerToken
		}

		raw, err := json.Marshal(existing)
		if err != nil {
			return err
		}
		s.CAConfig = string(raw)

	case types.DeviceAuthCATypeSCEP:
		if req.SCEP == nil {
			return nil
		}
		var existing struct {
			URL            string `json:"url"`
			Challenge      string `json:"challenge"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if s.CAConfig != "" {
			if err := json.Unmarshal([]byte(s.CAConfig), &existing); err != nil {
				return err
			}
		}

		existing.URL = req.SCEP.URL
		existing.TimeoutSeconds = req.SCEP.TimeoutSeconds
		if req.SCEP.Challenge != "" {
			existing.Challenge = req.SCEP.Challenge
		}

		raw, err := json.Marshal(existing)
		if err != nil {
			return err
		}
		s.CAConfig = string(raw)
	}

	return nil
}
