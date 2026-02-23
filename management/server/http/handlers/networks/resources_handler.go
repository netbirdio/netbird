package networks

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

type resourceHandler struct {
	resourceManager resources.Manager
	groupsManager   groups.Manager
}

func addResourceEndpoints(resourcesManager resources.Manager, groupsManager groups.Manager, permissionsManager permissions.Manager, router *mux.Router) {
	resourceHandler := newResourceHandler(resourcesManager, groupsManager)
	router.HandleFunc("/networks/resources", permissionsManager.WithPermission(modules.Networks, operations.Read, resourceHandler.getAllResourcesInAccount)).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources", permissionsManager.WithPermission(modules.Networks, operations.Read, resourceHandler.getAllResourcesInNetwork)).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources", permissionsManager.WithPermission(modules.Networks, operations.Create, resourceHandler.createResource)).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", permissionsManager.WithPermission(modules.Networks, operations.Read, resourceHandler.getResource)).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", permissionsManager.WithPermission(modules.Networks, operations.Update, resourceHandler.updateResource)).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", permissionsManager.WithPermission(modules.Networks, operations.Delete, resourceHandler.deleteResource)).Methods("DELETE", "OPTIONS")
}

func newResourceHandler(resourceManager resources.Manager, groupsManager groups.Manager) *resourceHandler {
	return &resourceHandler{
		resourceManager: resourceManager,
		groupsManager:   groupsManager,
	}
}

func (h *resourceHandler) getAllResourcesInNetwork(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	networkID := mux.Vars(r)["networkId"]
	resources, err := h.resourceManager.GetAllResourcesInNetwork(r.Context(), userAuth.AccountId, userAuth.UserId, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, len(resources))

	var resourcesResponse []*api.NetworkResource
	for _, resource := range resources {
		resourcesResponse = append(resourcesResponse, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
	}

	util.WriteJSONObject(r.Context(), w, resourcesResponse)
}
func (h *resourceHandler) getAllResourcesInAccount(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	resources, err := h.resourceManager.GetAllResourcesInAccount(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	resourcesResponse := make([]*api.NetworkResource, 0, len(resources))
	for _, resource := range resources {
		resourcesResponse = append(resourcesResponse, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
	}

	util.WriteJSONObject(r.Context(), w, resourcesResponse)
}

func (h *resourceHandler) createResource(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	var req api.NetworkResourceRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	resource := &types.NetworkResource{}
	resource.FromAPIRequest(&req)

	resource.NetworkID = mux.Vars(r)["networkId"]
	resource.AccountID = userAuth.AccountId
	resource, err = h.resourceManager.CreateResource(r.Context(), userAuth.UserId, resource)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	util.WriteJSONObject(r.Context(), w, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
}

func (h *resourceHandler) getResource(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	networkID := mux.Vars(r)["networkId"]
	resourceID := mux.Vars(r)["resourceId"]
	resource, err := h.resourceManager.GetResource(r.Context(), userAuth.AccountId, userAuth.UserId, networkID, resourceID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	util.WriteJSONObject(r.Context(), w, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
}

func (h *resourceHandler) updateResource(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	var req api.NetworkResourceRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	resource := &types.NetworkResource{}
	resource.FromAPIRequest(&req)

	resource.ID = mux.Vars(r)["resourceId"]
	resource.NetworkID = mux.Vars(r)["networkId"]
	resource.AccountID = userAuth.AccountId
	resource, err = h.resourceManager.UpdateResource(r.Context(), userAuth.UserId, resource)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	util.WriteJSONObject(r.Context(), w, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
}

func (h *resourceHandler) deleteResource(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	networkID := mux.Vars(r)["networkId"]
	resourceID := mux.Vars(r)["resourceId"]
	err := h.resourceManager.DeleteResource(r.Context(), userAuth.AccountId, userAuth.UserId, networkID, resourceID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
