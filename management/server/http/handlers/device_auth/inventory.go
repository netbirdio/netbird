package device_auth

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// ─── Response types ────────────────────────────────────────────────────────────

// inventoryConfigResponse is the response body for GET|PUT /device-auth/inventory/config.
// All three sources are always present in the response; enabled:false means not configured.
// Sensitive credential fields are always returned as empty strings; their
// presence is indicated by the corresponding has_* boolean field.
type inventoryConfigResponse struct {
	Static *staticInvResp    `json:"static"`
	Intune *intuneConfigResp `json:"intune"`
	Jamf   *jamfConfigResp   `json:"jamf"`
}

type staticInvResp struct {
	Enabled bool     `json:"enabled"`
	Peers   []string `json:"peers"`
	Serials []string `json:"serials"`
}

type intuneConfigResp struct {
	Enabled           bool   `json:"enabled"`
	TenantID          string `json:"tenant_id"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`    // always "" in responses
	HasClientSecret   bool   `json:"has_client_secret"` // true when a secret is stored
	RequireCompliance bool   `json:"require_compliance"`
}

type jamfConfigResp struct {
	Enabled           bool   `json:"enabled"`
	JamfURL           string `json:"jamf_url"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"` // always "" in responses
	HasClientSecret   bool   `json:"has_client_secret"` // true when a secret is stored
	RequireManagement bool   `json:"require_management"`
}

// ─── Request types ─────────────────────────────────────────────────────────────

// inventoryConfigRequest is the request body for PUT /device-auth/inventory/config.
// Send only the sources you want to update; omitted sources are left unchanged.
type inventoryConfigRequest struct {
	Static *staticInvReq    `json:"static,omitempty"`
	Intune *intuneConfigReq `json:"intune,omitempty"`
	Jamf   *jamfConfigReq   `json:"jamf,omitempty"`
}

type staticInvReq struct {
	Enabled bool      `json:"enabled"`
	Peers   []string  `json:"peers"`
	Serials *[]string `json:"serials,omitempty"` // nil = preserve existing
}

type intuneConfigReq struct {
	Enabled           bool   `json:"enabled"`
	TenantID          string `json:"tenant_id"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"` // empty means "preserve existing"
	RequireCompliance bool   `json:"require_compliance"`
}

type jamfConfigReq struct {
	Enabled           bool   `json:"enabled"`
	JamfURL           string `json:"jamf_url"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"` // empty means "preserve existing"
	RequireManagement bool   `json:"require_management"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// getInventoryConfig returns the multi-source inventory configuration for the account.
// Credential fields (client_secret) are always redacted; their presence
// is indicated by the corresponding has_* boolean field.
func (h *handler) getInventoryConfig(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	accountSettings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp, err := buildInventoryConfigResponse(accountSettings.DeviceAuth)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

// putInventoryConfig replaces the multi-source inventory configuration for the account.
// When a credential field (client_secret) is sent as an empty string, the existing
// stored credential is preserved unchanged.
func (h *handler) putInventoryConfig(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	var req inventoryConfigRequest
	// Limit body to 1 MiB to prevent memory exhaustion from oversized payloads.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	// Use LockingStrengthUpdate to serialize concurrent inventory config updates.
	accountSettings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if accountSettings.DeviceAuth == nil {
		accountSettings.DeviceAuth = &types.DeviceAuthSettings{}
	}

	if err := applyInventoryConfigRequest(accountSettings.DeviceAuth, req); err != nil {
		util.WriteErrorResponse("invalid inventory config: "+err.Error(), http.StatusBadRequest, w)
		return
	}

	if err := h.store.SaveAccountSettings(r.Context(), userAuth.AccountId, accountSettings); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp, err := buildInventoryConfigResponse(accountSettings.DeviceAuth)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// multiStoredConfig is the internal JSON format stored in DeviceAuthSettings.InventoryConfig.
type multiStoredConfig struct {
	Static *storedStaticConfig `json:"static,omitempty"`
	Intune *storedIntuneConfig `json:"intune,omitempty"`
	Jamf   *storedJamfConfig   `json:"jamf,omitempty"`
}

type storedStaticConfig struct {
	Enabled bool     `json:"enabled"`
	Peers   []string `json:"peers"`
	Serials []string `json:"serials"`
}

type storedIntuneConfig struct {
	Enabled           bool   `json:"enabled"`
	TenantID          string `json:"tenant_id"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	RequireCompliance bool   `json:"require_compliance"`
}

type storedJamfConfig struct {
	Enabled           bool   `json:"enabled"`
	JamfURL           string `json:"jamf_url"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	RequireManagement bool   `json:"require_management"`
}

// buildInventoryConfigResponse constructs a redacted inventoryConfigResponse from DeviceAuthSettings.
// All three sources are always present in the response; enabled:false means not configured.
func buildInventoryConfigResponse(s *types.DeviceAuthSettings) (*inventoryConfigResponse, error) {
	resp := &inventoryConfigResponse{
		Static: &staticInvResp{Enabled: false, Peers: []string{}, Serials: []string{}},
		Intune: &intuneConfigResp{Enabled: false},
		Jamf:   &jamfConfigResp{Enabled: false},
	}

	if s == nil || s.InventoryConfig == "" {
		return resp, nil
	}

	var cfg multiStoredConfig
	if err := json.Unmarshal([]byte(s.InventoryConfig), &cfg); err != nil {
		return nil, err
	}

	if cfg.Static != nil {
		peers := cfg.Static.Peers
		if peers == nil {
			peers = []string{}
		}
		serials := cfg.Static.Serials
		if serials == nil {
			serials = []string{}
		}
		resp.Static = &staticInvResp{
			Enabled: cfg.Static.Enabled,
			Peers:   peers,
			Serials: serials,
		}
	}

	if cfg.Intune != nil {
		resp.Intune = &intuneConfigResp{
			Enabled:           cfg.Intune.Enabled,
			TenantID:          cfg.Intune.TenantID,
			ClientID:          cfg.Intune.ClientID,
			ClientSecret:      "",
			HasClientSecret:   cfg.Intune.ClientSecret != "",
			RequireCompliance: cfg.Intune.RequireCompliance,
		}
	}

	if cfg.Jamf != nil {
		resp.Jamf = &jamfConfigResp{
			Enabled:           cfg.Jamf.Enabled,
			JamfURL:           cfg.Jamf.JamfURL,
			ClientID:          cfg.Jamf.ClientID,
			ClientSecret:      "",
			HasClientSecret:   cfg.Jamf.ClientSecret != "",
			RequireManagement: cfg.Jamf.RequireManagement,
		}
	}

	return resp, nil
}

// applyInventoryConfigRequest merges the request into s.InventoryConfig.
// Only sources present in the request are updated; absent sources are left unchanged.
// When a credential field (client_secret) is empty in the request, the existing
// stored credential is preserved.
func applyInventoryConfigRequest(s *types.DeviceAuthSettings, req inventoryConfigRequest) error {
	var cfg multiStoredConfig
	if s.InventoryConfig != "" {
		if err := json.Unmarshal([]byte(s.InventoryConfig), &cfg); err != nil {
			return err
		}
	}

	if req.Static != nil {
		peers := req.Static.Peers
		if peers == nil {
			peers = []string{}
		}
		// Preserve existing serials; they are managed separately (serial count only exposed in GET).
		existing := storedStaticConfig{}
		if cfg.Static != nil {
			existing = *cfg.Static
		}
		existing.Enabled = req.Static.Enabled
		existing.Peers = peers
		// If serials were explicitly sent, replace them; nil means preserve existing.
		if req.Static.Serials != nil {
			existing.Serials = *req.Static.Serials
			if existing.Serials == nil {
				existing.Serials = []string{}
			}
		}
		cfg.Static = &existing
	}

	if req.Intune != nil {
		existing := storedIntuneConfig{}
		if cfg.Intune != nil {
			existing = *cfg.Intune
		}
		existing.Enabled = req.Intune.Enabled
		existing.TenantID = req.Intune.TenantID
		existing.ClientID = req.Intune.ClientID
		existing.RequireCompliance = req.Intune.RequireCompliance
		// Preserve credential when empty string is sent.
		if req.Intune.ClientSecret != "" {
			existing.ClientSecret = req.Intune.ClientSecret
		}
		cfg.Intune = &existing
	}

	if req.Jamf != nil {
		existing := storedJamfConfig{}
		if cfg.Jamf != nil {
			existing = *cfg.Jamf
		}
		existing.Enabled = req.Jamf.Enabled
		existing.JamfURL = req.Jamf.JamfURL
		existing.ClientID = req.Jamf.ClientID
		existing.RequireManagement = req.Jamf.RequireManagement
		// Preserve credential when empty string is sent.
		if req.Jamf.ClientSecret != "" {
			existing.ClientSecret = req.Jamf.ClientSecret
		}
		cfg.Jamf = &existing
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	s.InventoryConfig = string(raw)

	return nil
}
