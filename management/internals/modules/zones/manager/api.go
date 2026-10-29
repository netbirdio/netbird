package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager zones.Manager
}

func RegisterEndpoints(router *mux.Router, manager zones.Manager) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/dns/zones", h.getAllZones).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/zones", h.createZone).Methods("POST", "OPTIONS")
	router.HandleFunc("/dns/zones/{zoneId}", h.getZone).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/zones/{zoneId}", h.updateZone).Methods("PUT", "OPTIONS")
	router.HandleFunc("/dns/zones/{zoneId}", h.deleteZone).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllZones(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allZones, err := h.manager.GetAllZones(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiZones := make([]*api.Zone, 0, len(allZones))
	for _, zone := range allZones {
		apiZones = append(apiZones, zone.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, apiZones)
}

func (h *handler) createZone(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PostApiDnsZonesJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	zone := new(zones.Zone)
	zone.FromAPIRequest(&req)

	if err = zone.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	createdZone, err := h.manager.CreateZone(r.Context(), userAuth.AccountId, userAuth.UserId, zone)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, createdZone.ToAPIResponse())
}

func (h *handler) getZone(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	zoneID := mux.Vars(r)["zoneId"]
	if zoneID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "zone ID is required"), w)
		return
	}

	zone, err := h.manager.GetZone(r.Context(), userAuth.AccountId, userAuth.UserId, zoneID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, zone.ToAPIResponse())
}

func (h *handler) updateZone(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	zoneID := mux.Vars(r)["zoneId"]
	if zoneID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "zone ID is required"), w)
		return
	}

	var req api.PutApiDnsZonesZoneIdJSONRequestBody
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	zone := new(zones.Zone)
	zone.FromAPIRequest(&req)
	zone.ID = zoneID

	if err = zone.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	updatedZone, err := h.manager.UpdateZone(r.Context(), userAuth.AccountId, userAuth.UserId, zone)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updatedZone.ToAPIResponse())
}

func (h *handler) deleteZone(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	zoneID := mux.Vars(r)["zoneId"]
	if zoneID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "zone ID is required"), w)
		return
	}

	if err = h.manager.DeleteZone(r.Context(), userAuth.AccountId, userAuth.UserId, zoneID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
