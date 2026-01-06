package instance

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbinstance "github.com/netbirdio/netbird/management/server/instance"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// handler handles the instance setup HTTP endpoints
type handler struct {
	instanceManager nbinstance.Manager
}

// AddEndpoints registers the instance setup endpoints.
// These endpoints bypass authentication for initial setup.
func AddEndpoints(instanceManager nbinstance.Manager, router *mux.Router) {
	h := &handler{
		instanceManager: instanceManager,
	}

	router.HandleFunc("/instance", h.getInstanceStatus).Methods("GET", "OPTIONS")
	router.HandleFunc("/setup", h.setup).Methods("POST", "OPTIONS")
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

	util.WriteJSONObject(r.Context(), w, api.InstanceStatus{
		SetupRequired: setupRequired,
	})
}

// setup creates the initial admin user for the instance.
// This endpoint is unauthenticated but only works when setup is required.
func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	var req api.SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("invalid request body", http.StatusBadRequest, w)
		return
	}

	userData, err := h.instanceManager.CreateOwnerUser(r.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	log.WithContext(r.Context()).Infof("instance setup completed: created user %s", req.Email)

	util.WriteJSONObject(r.Context(), w, api.SetupResponse{
		UserId: userData.ID,
		Email:  userData.Email,
	})
}
