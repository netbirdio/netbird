package instance

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbinstance "github.com/netbirdio/netbird/management/server/instance"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// handler handles the instance setup HTTP endpoints
type handler struct {
	instanceManager nbinstance.Manager
	setupManager    *nbinstance.SetupService
}

// AddEndpoints registers the instance setup endpoints.
// These endpoints bypass authentication for initial setup.
func AddEndpoints(instanceManager nbinstance.Manager, accountManager account.Manager, router *mux.Router) {
	h := &handler{
		instanceManager: instanceManager,
		setupManager:    nbinstance.NewSetupService(instanceManager, accountManager),
	}

	router.HandleFunc("/instance", h.getInstanceStatus).Methods("GET", "OPTIONS")
	router.HandleFunc("/setup", h.setup).Methods("POST", "OPTIONS")
}

// AddVersionEndpoint registers the authenticated version endpoint.
func AddVersionEndpoint(instanceManager nbinstance.Manager, router *mux.Router) {
	h := &handler{
		instanceManager: instanceManager,
	}

	router.HandleFunc("/instance/version", h.getVersionInfo).Methods("GET", "OPTIONS")
}

// getInstanceStatus returns the instance status including whether setup is required.
// This endpoint is unauthenticated.
func (h *handler) getInstanceStatus(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := h.instanceManager.IsSetupRequired(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to check setup status: %v", err)
		util.WriteErrorResponse("failed to check instance status", http.StatusInternalServerError, w)
		return
	}
	log.WithContext(r.Context()).Infof("instance setup status: %v", setupRequired)
	util.WriteJSONObject(r.Context(), w, api.InstanceStatus{
		SetupRequired: setupRequired,
	})
}

// setup creates the initial admin user for the instance.
// This endpoint is unauthenticated but only works when setup is required.
func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req api.SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("invalid request body", http.StatusBadRequest, w)
		return
	}

	result, err := h.setupManager.SetupOwner(ctx, req.Email, req.Password, req.Name, nbinstance.SetupOptions{
		CreatePAT:       req.CreatePat != nil && *req.CreatePat,
		PATExpireInDays: req.PatExpireIn,
	})
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	log.WithContext(ctx).Infof("instance setup completed: created user %s", req.Email)

	resp := api.SetupResponse{
		UserId: result.User.ID,
		Email:  result.User.Email,
	}

	if result.PATPlainToken != "" {
		resp.PersonalAccessToken = &result.PATPlainToken
	}

	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(ctx, w, resp)
}

// getVersionInfo returns version information for NetBird components.
// This endpoint requires authentication.
func (h *handler) getVersionInfo(w http.ResponseWriter, r *http.Request) {
	versionInfo, err := h.instanceManager.GetVersionInfo(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to get version info: %v", err)
		util.WriteErrorResponse("failed to get version info", http.StatusInternalServerError, w)
		return
	}

	resp := api.InstanceVersionInfo{
		ManagementCurrentVersion:  versionInfo.CurrentVersion,
		ManagementUpdateAvailable: versionInfo.ManagementUpdateAvailable,
	}

	if versionInfo.DashboardVersion != "" {
		resp.DashboardAvailableVersion = &versionInfo.DashboardVersion
	}

	if versionInfo.ManagementVersion != "" {
		resp.ManagementAvailableVersion = &versionInfo.ManagementVersion
	}

	util.WriteJSONObject(r.Context(), w, resp)
}
