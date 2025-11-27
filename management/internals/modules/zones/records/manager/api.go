package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager records.Manager
}

func RegisterEndpoints(router *mux.Router, manager records.Manager) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/dns/zones/{zoneId}/records", h.getAllRecords).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/zones/{zoneId}/records", h.createRecord).Methods("POST", "OPTIONS")
	router.HandleFunc("/dns/zones/{zoneId}/records/{recordId}", h.getRecord).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/zones/{zoneId}/records/{recordId}", h.updateRecord).Methods("PUT", "OPTIONS")
	router.HandleFunc("/dns/zones/{zoneId}/records/{recordId}", h.deleteRecord).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllRecords(w http.ResponseWriter, r *http.Request) {
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

	allRecords, err := h.manager.GetAllRecords(r.Context(), userAuth.AccountId, userAuth.UserId, zoneID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiRecords := make([]*api.DNSRecord, 0, len(allRecords))
	for _, record := range allRecords {
		apiRecords = append(apiRecords, record.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, apiRecords)
}

func (h *handler) createRecord(w http.ResponseWriter, r *http.Request) {
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

	var req api.PostApiDnsZonesZoneIdRecordsJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	record := new(records.Record)
	record.FromAPIRequest(&req)

	if err = record.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	createdRecord, err := h.manager.CreateRecord(r.Context(), userAuth.AccountId, userAuth.UserId, zoneID, record)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, createdRecord.ToAPIResponse())
}

func (h *handler) getRecord(w http.ResponseWriter, r *http.Request) {
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

	recordID := mux.Vars(r)["recordId"]
	if recordID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "record ID is required"), w)
		return
	}

	record, err := h.manager.GetRecord(r.Context(), userAuth.AccountId, userAuth.UserId, zoneID, recordID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, record.ToAPIResponse())
}

func (h *handler) updateRecord(w http.ResponseWriter, r *http.Request) {
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

	recordID := mux.Vars(r)["recordId"]
	if recordID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "record ID is required"), w)
		return
	}

	var req api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	record := new(records.Record)
	record.FromAPIRequest(&req)
	record.ID = recordID

	if err = record.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	updatedRecord, err := h.manager.UpdateRecord(r.Context(), userAuth.AccountId, userAuth.UserId, zoneID, record)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updatedRecord.ToAPIResponse())
}

func (h *handler) deleteRecord(w http.ResponseWriter, r *http.Request) {
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

	recordID := mux.Vars(r)["recordId"]
	if recordID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "record ID is required"), w)
		return
	}

	if err = h.manager.DeleteRecord(r.Context(), userAuth.AccountId, userAuth.UserId, zoneID, recordID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
