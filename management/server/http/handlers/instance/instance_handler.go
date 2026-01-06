package instance

import (
	"encoding/json"
	"net/http"
	"net/mail"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbinstance "github.com/netbirdio/netbird/management/server/instance"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
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
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to check setup status"), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, api.InstanceStatus{
		SetupRequired: setupRequired,
	})
}

// setup creates the initial admin user for the instance.
// This endpoint is unauthenticated but only works when setup is required.
func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	// Check if setup is still required
	setupRequired, err := h.instanceManager.IsSetupRequired(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to check setup status: %v", err)
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to check setup status"), w)
		return
	}

	if !setupRequired {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "setup already completed"), w)
		return
	}

	var req api.SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("invalid request body", http.StatusBadRequest, w)
		return
	}

	// Validate request
	email := req.Email
	if email == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "email is required"), w)
		return
	}
	if _, err := mail.ParseAddress(email); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid email format"), w)
		return
	}
	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "name is required"), w)
		return
	}
	if req.Password == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "password is required"), w)
		return
	}
	if len(req.Password) < 8 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "password must be at least 8 characters"), w)
		return
	}

	// Create the owner user via instance manager
	userData, err := h.instanceManager.CreateOwnerUser(r.Context(), email, req.Password, req.Name)
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to create user during setup: %v", err)
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to create user: %v", err), w)
		return
	}

	log.WithContext(r.Context()).Infof("instance setup completed: created user %s", email)

	util.WriteJSONObject(r.Context(), w, api.SetupResponse{
		UserId: userData.ID,
		Email:  userData.Email,
	})
}
