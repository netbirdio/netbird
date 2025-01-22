package networks

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
)

type resourceHandler struct {
	resourceManager  resources.Manager
	groupsManager    groups.Manager
	extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error)
	claimsExtractor  *jwtclaims.ClaimsExtractor
}

func addResourceEndpoints(resourcesManager resources.Manager, groupsManager groups.Manager, extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error), authCfg configs.AuthCfg, router *mux.Router) {
	resourceHandler := newResourceHandler(resourcesManager, groupsManager, extractFromToken, authCfg)
	router.HandleFunc("/networks/resources", resourceHandler.getAllResourcesInAccount).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources", resourceHandler.getAllResourcesInNetwork).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources", resourceHandler.createResource).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", resourceHandler.getResource).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", resourceHandler.updateResource).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", resourceHandler.deleteResource).Methods("DELETE", "OPTIONS")
}

func newResourceHandler(resourceManager resources.Manager, groupsManager groups.Manager, extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error), authCfg configs.AuthCfg) *resourceHandler {
	return &resourceHandler{
		resourceManager:  resourceManager,
		groupsManager:    groupsManager,
		extractFromToken: extractFromToken,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

func (h *resourceHandler) getAllResourcesInNetwork(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	networkID := mux.Vars(r)["networkId"]
	resources, err := h.resourceManager.GetAllResourcesInNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), accountID, userID)
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
func (h *resourceHandler) getAllResourcesInAccount(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resources, err := h.resourceManager.GetAllResourcesInAccount(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	var resourcesResponse []*api.NetworkResource
	for _, resource := range resources {
		resourcesResponse = append(resourcesResponse, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
	}

	util.WriteJSONObject(r.Context(), w, resourcesResponse)
}

func (h *resourceHandler) createResource(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.NetworkResourceRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	resource := &types.NetworkResource{}
	resource.FromAPIRequest(&req)

	resource.NetworkID = mux.Vars(r)["networkId"]
	resource.AccountID = accountID
	resource.Enabled = true
	resource, err = h.resourceManager.CreateResource(r.Context(), userID, resource)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	util.WriteJSONObject(r.Context(), w, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
}

func (h *resourceHandler) getResource(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	networkID := mux.Vars(r)["networkId"]
	resourceID := mux.Vars(r)["resourceId"]
	resource, err := h.resourceManager.GetResource(r.Context(), accountID, userID, networkID, resourceID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	util.WriteJSONObject(r.Context(), w, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
}

func (h *resourceHandler) updateResource(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.NetworkResourceRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	resource := &types.NetworkResource{}
	resource.FromAPIRequest(&req)

	resource.ID = mux.Vars(r)["resourceId"]
	resource.NetworkID = mux.Vars(r)["networkId"]
	resource.AccountID = accountID
	resource, err = h.resourceManager.UpdateResource(r.Context(), userID, resource)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grps, err := h.groupsManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	util.WriteJSONObject(r.Context(), w, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
}

func (h *resourceHandler) deleteResource(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	networkID := mux.Vars(r)["networkId"]
	resourceID := mux.Vars(r)["resourceId"]
	err = h.resourceManager.DeleteResource(r.Context(), accountID, userID, networkID, resourceID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
