// Package entra_device_auth hosts the admin (account-scoped) CRUD endpoints
// for configuring the Entra device authentication integration. Enrolment
// itself lives in the entra_join package on /join/entra.
package entra_device_auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	ed "github.com/netbirdio/netbird/management/server/integrations/entra_device"
	"github.com/netbirdio/netbird/management/server/types"
)

// AccountResolver returns the account & user IDs for the calling principal.
// Implementations should inspect the auth middleware's context values, matching
// how existing admin handlers work (see nbcontext.GetUserAuthFromContext).
type AccountResolver func(r *http.Request) (accountID, userID string, err error)

// PermissionChecker must return true iff the calling user may perform the given
// operation on the Entra device auth module. The existing permissions manager
// (`modules.EntraDeviceAuth`) can be wired in here without touching the
// handler.
type PermissionChecker func(ctx context.Context, accountID, userID, operation string) (bool, error)

// Handler serves the admin API for configuring the integration.
type Handler struct {
	Store       ed.Store
	ResolveAuth AccountResolver
	Permit      PermissionChecker
}

// Register wires the admin routes onto the given router. Typical usage:
//
//	adminHandler.Register(apiV1Router)
//
// where apiV1Router is the existing authenticated /api subrouter.
func (h *Handler) Register(r *mux.Router) {
	r.HandleFunc("/integrations/entra-device-auth", h.getIntegration).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/integrations/entra-device-auth", h.putIntegration).Methods(http.MethodPost, http.MethodPut, http.MethodOptions)
	r.HandleFunc("/integrations/entra-device-auth", h.deleteIntegration).Methods(http.MethodDelete, http.MethodOptions)

	r.HandleFunc("/integrations/entra-device-auth/mappings", h.listMappings).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/integrations/entra-device-auth/mappings", h.createMapping).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/integrations/entra-device-auth/mappings/{id}", h.getMapping).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/integrations/entra-device-auth/mappings/{id}", h.updateMapping).Methods(http.MethodPut, http.MethodOptions)
	r.HandleFunc("/integrations/entra-device-auth/mappings/{id}", h.deleteMapping).Methods(http.MethodDelete, http.MethodOptions)
}

// --- integration ---

// integrationDTO is the write/read shape for the integration config. The
// ClientSecret is write-only — on GET it is masked.
type integrationDTO struct {
	ID                      string                  `json:"id,omitempty"`
	TenantID                string                  `json:"tenant_id"`
	ClientID                string                  `json:"client_id"`
	ClientSecret            string                  `json:"client_secret,omitempty"`
	Issuer                  string                  `json:"issuer,omitempty"`
	Audience                string                  `json:"audience,omitempty"`
	Enabled                 bool                    `json:"enabled"`
	RequireIntuneCompliant  bool                    `json:"require_intune_compliant"`
	AllowTenantOnlyFallback bool                    `json:"allow_tenant_only_fallback"`
	FallbackAutoGroups      []string                `json:"fallback_auto_groups,omitempty"`
	MappingResolution       types.MappingResolution `json:"mapping_resolution,omitempty"`
	RevalidationInterval    string                  `json:"revalidation_interval,omitempty"` // e.g. "24h"
	CreatedAt               time.Time               `json:"created_at,omitempty"`
	UpdatedAt               time.Time               `json:"updated_at,omitempty"`
}

func (h *Handler) getIntegration(w http.ResponseWriter, r *http.Request) {
	accountID, userID, err := h.auth(r, "read")
	if err != nil {
		httpErr(w, err)
		return
	}
	_ = userID
	a, err := h.Store.GetEntraDeviceAuth(r.Context(), accountID)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	if a == nil {
		httpJSON(w, http.StatusNotFound, apiError{"not_found", "no integration configured for this account"})
		return
	}
	httpJSON(w, http.StatusOK, toIntegrationDTO(a, false))
}

func (h *Handler) putIntegration(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.auth(r, "update")
	if err != nil {
		httpErr(w, err)
		return
	}
	var in integrationDTO
	if err := readJSON(r, &in); err != nil {
		httpJSON(w, http.StatusBadRequest, apiError{"invalid_json", err.Error()})
		return
	}
	existing, err := h.Store.GetEntraDeviceAuth(r.Context(), accountID)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	auth := existing
	if auth == nil {
		auth = types.NewEntraDeviceAuth(accountID)
	}
	applyDTOToAuth(auth, &in)
	if auth.TenantID == "" || auth.ClientID == "" {
		httpJSON(w, http.StatusBadRequest,
			apiError{"invalid_request", "tenant_id and client_id are required"})
		return
	}
	// Only overwrite the secret if the caller supplied a new one (so a GET-
	// then-PUT roundtrip doesn't inadvertently wipe the secret).
	if strings.TrimSpace(in.ClientSecret) != "" {
		auth.ClientSecret = in.ClientSecret
	}
	auth.UpdatedAt = time.Now().UTC()
	if err := h.Store.SaveEntraDeviceAuth(r.Context(), auth); err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	httpJSON(w, http.StatusOK, toIntegrationDTO(auth, false))
}

func (h *Handler) deleteIntegration(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.auth(r, "delete")
	if err != nil {
		httpErr(w, err)
		return
	}
	if err := h.Store.DeleteEntraDeviceAuth(r.Context(), accountID); err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- mappings ---

type mappingDTO struct {
	ID                  string     `json:"id,omitempty"`
	Name                string     `json:"name"`
	EntraGroupID        string     `json:"entra_group_id"`
	AutoGroups          []string   `json:"auto_groups"`
	Ephemeral           bool       `json:"ephemeral"`
	AllowExtraDNSLabels bool       `json:"allow_extra_dns_labels"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	Revoked             bool       `json:"revoked"`
	Priority            int        `json:"priority"`
	CreatedAt           time.Time  `json:"created_at,omitempty"`
	UpdatedAt           time.Time  `json:"updated_at,omitempty"`
}

func (h *Handler) listMappings(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.auth(r, "read")
	if err != nil {
		httpErr(w, err)
		return
	}
	ms, err := h.Store.ListEntraDeviceMappings(r.Context(), accountID)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	out := make([]mappingDTO, 0, len(ms))
	for _, m := range ms {
		out = append(out, toMappingDTO(m))
	}
	httpJSON(w, http.StatusOK, out)
}

func (h *Handler) createMapping(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.auth(r, "create")
	if err != nil {
		httpErr(w, err)
		return
	}
	var in mappingDTO
	if err := readJSON(r, &in); err != nil {
		httpJSON(w, http.StatusBadRequest, apiError{"invalid_json", err.Error()})
		return
	}
	integ, err := h.Store.GetEntraDeviceAuth(r.Context(), accountID)
	if err != nil || integ == nil {
		httpJSON(w, http.StatusConflict, apiError{"no_integration",
			"configure the Entra device auth integration before adding mappings"})
		return
	}
	m := types.NewEntraDeviceAuthMapping(accountID, integ.ID, in.Name, in.EntraGroupID, in.AutoGroups)
	m.Ephemeral = in.Ephemeral
	m.AllowExtraDNSLabels = in.AllowExtraDNSLabels
	m.Priority = in.Priority
	m.Revoked = in.Revoked
	m.ExpiresAt = in.ExpiresAt
	if err := h.Store.SaveEntraDeviceMapping(r.Context(), m); err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	httpJSON(w, http.StatusCreated, toMappingDTO(m))
}

func (h *Handler) getMapping(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.auth(r, "read")
	if err != nil {
		httpErr(w, err)
		return
	}
	id := mux.Vars(r)["id"]
	m, err := h.Store.GetEntraDeviceMapping(r.Context(), accountID, id)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	if m == nil {
		httpJSON(w, http.StatusNotFound, apiError{"not_found", "mapping not found"})
		return
	}
	httpJSON(w, http.StatusOK, toMappingDTO(m))
}

func (h *Handler) updateMapping(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.auth(r, "update")
	if err != nil {
		httpErr(w, err)
		return
	}
	id := mux.Vars(r)["id"]
	existing, err := h.Store.GetEntraDeviceMapping(r.Context(), accountID, id)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	if existing == nil {
		httpJSON(w, http.StatusNotFound, apiError{"not_found", "mapping not found"})
		return
	}
	var in mappingDTO
	if err := readJSON(r, &in); err != nil {
		httpJSON(w, http.StatusBadRequest, apiError{"invalid_json", err.Error()})
		return
	}
	existing.Name = in.Name
	existing.EntraGroupID = in.EntraGroupID
	existing.AutoGroups = append([]string(nil), in.AutoGroups...)
	existing.Ephemeral = in.Ephemeral
	existing.AllowExtraDNSLabels = in.AllowExtraDNSLabels
	existing.ExpiresAt = in.ExpiresAt
	existing.Revoked = in.Revoked
	existing.Priority = in.Priority
	existing.UpdatedAt = time.Now().UTC()
	if err := h.Store.SaveEntraDeviceMapping(r.Context(), existing); err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	httpJSON(w, http.StatusOK, toMappingDTO(existing))
}

func (h *Handler) deleteMapping(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.auth(r, "delete")
	if err != nil {
		httpErr(w, err)
		return
	}
	id := mux.Vars(r)["id"]
	if err := h.Store.DeleteEntraDeviceMapping(r.Context(), accountID, id); err != nil {
		httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func (h *Handler) auth(r *http.Request, op string) (string, string, error) {
	if h.ResolveAuth == nil {
		return "", "", &httpError{
			status: http.StatusInternalServerError,
			code:   "internal_error",
			msg:    "handler misconfigured (no AccountResolver)",
		}
	}
	accountID, userID, err := h.ResolveAuth(r)
	if err != nil {
		return "", "", &httpError{
			status: http.StatusUnauthorized, code: "unauthorized", msg: err.Error(),
		}
	}
	if h.Permit != nil {
		ok, err := h.Permit(r.Context(), accountID, userID, op)
		if err != nil {
			return "", "", &httpError{
				status: http.StatusInternalServerError,
				code:   "permission_check_failed",
				msg:    err.Error(),
			}
		}
		if !ok {
			return "", "", &httpError{
				status: http.StatusForbidden, code: "forbidden",
				msg: "missing permission " + op + " on entra_device_auth",
			}
		}
	}
	return accountID, userID, nil
}

func applyDTOToAuth(a *types.EntraDeviceAuth, dto *integrationDTO) {
	a.TenantID = strings.TrimSpace(dto.TenantID)
	a.ClientID = strings.TrimSpace(dto.ClientID)
	a.Issuer = strings.TrimSpace(dto.Issuer)
	a.Audience = strings.TrimSpace(dto.Audience)
	a.Enabled = dto.Enabled
	a.RequireIntuneCompliant = dto.RequireIntuneCompliant
	a.AllowTenantOnlyFallback = dto.AllowTenantOnlyFallback
	a.FallbackAutoGroups = append([]string(nil), dto.FallbackAutoGroups...)
	if dto.MappingResolution != "" {
		a.MappingResolution = dto.MappingResolution
	}
	if dto.RevalidationInterval != "" {
		if d, err := time.ParseDuration(dto.RevalidationInterval); err == nil {
			a.RevalidationInterval = d
		}
	}
}

func toIntegrationDTO(a *types.EntraDeviceAuth, includeSecret bool) integrationDTO {
	out := integrationDTO{
		ID:                      a.ID,
		TenantID:                a.TenantID,
		ClientID:                a.ClientID,
		Issuer:                  a.Issuer,
		Audience:                a.Audience,
		Enabled:                 a.Enabled,
		RequireIntuneCompliant:  a.RequireIntuneCompliant,
		AllowTenantOnlyFallback: a.AllowTenantOnlyFallback,
		FallbackAutoGroups:      a.FallbackAutoGroups,
		MappingResolution:       a.ResolutionOrDefault(),
		CreatedAt:               a.CreatedAt,
		UpdatedAt:               a.UpdatedAt,
	}
	if a.RevalidationInterval > 0 {
		out.RevalidationInterval = a.RevalidationInterval.String()
	}
	if includeSecret {
		out.ClientSecret = a.ClientSecret
	} else if a.ClientSecret != "" {
		out.ClientSecret = "********"
	}
	return out
}

func toMappingDTO(m *types.EntraDeviceAuthMapping) mappingDTO {
	return mappingDTO{
		ID:                  m.ID,
		Name:                m.Name,
		EntraGroupID:        m.EntraGroupID,
		AutoGroups:          append([]string(nil), m.AutoGroups...),
		Ephemeral:           m.Ephemeral,
		AllowExtraDNSLabels: m.AllowExtraDNSLabels,
		ExpiresAt:           m.ExpiresAt,
		Revoked:             m.Revoked,
		Priority:            m.Priority,
		CreatedAt:           m.CreatedAt,
		UpdatedAt:           m.UpdatedAt,
	}
}

func readJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

func httpJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type httpError struct {
	status int
	code   string
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func httpErr(w http.ResponseWriter, err error) {
	if he, ok := err.(*httpError); ok {
		httpJSON(w, he.status, apiError{Code: he.code, Message: he.msg})
		return
	}
	httpJSON(w, http.StatusInternalServerError, apiError{"internal_error", err.Error()})
}
