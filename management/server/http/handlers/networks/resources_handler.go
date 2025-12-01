package networks

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type resourceHandler struct {
	resourceManager resources.Manager
	groupsManager   groups.Manager
	accountManager  account.Manager
}

func addResourceEndpoints(resourcesManager resources.Manager, groupsManager groups.Manager, accountManager account.Manager, router *mux.Router) {
	resourceHandler := newResourceHandler(resourcesManager, groupsManager, accountManager)
	router.HandleFunc("/networks/resources", resourceHandler.getAllResourcesInAccount).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources", resourceHandler.getAllResourcesInNetwork).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources", resourceHandler.createResource).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", resourceHandler.getResource).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", resourceHandler.updateResource).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}", resourceHandler.deleteResource).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/resources/{resourceId}/temporary-access", resourceHandler.CreateTemporaryAccess).Methods("POST", "OPTIONS")
}

func newResourceHandler(resourceManager resources.Manager, groupsManager groups.Manager, accountManager account.Manager) *resourceHandler {
	return &resourceHandler{
		resourceManager: resourceManager,
		groupsManager:   groupsManager,
		accountManager:  accountManager,
	}
}

func (h *resourceHandler) getAllResourcesInNetwork(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

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

	resourcesResponse := make([]*api.NetworkResource, 0, len(resources))
	for _, resource := range resources {
		resourcesResponse = append(resourcesResponse, resource.ToAPIResponse(grpsInfoMap[resource.ID]))
	}

	util.WriteJSONObject(r.Context(), w, resourcesResponse)
}

func (h *resourceHandler) createResource(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	networkID := mux.Vars(r)["networkId"]
	resourceID := mux.Vars(r)["resourceId"]
	err = h.resourceManager.DeleteResource(r.Context(), accountID, userID, networkID, resourceID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func (h *resourceHandler) CreateTemporaryAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	networkID := vars["networkId"]
	if len(networkID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid network ID"), w)
		return
	}
	resourceID := vars["resourceId"]
	if len(resourceID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid resource ID"), w)
		return
	}

	var req api.PeerTemporaryAccessRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	newPeer := &nbpeer.Peer{}
	newPeer.FromAPITemporaryAccessRequest(&req)

	targetResource, err := h.resourceManager.GetResource(r.Context(), userAuth.AccountId, userAuth.UserId, networkID, resourceID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	peer, _, _, err := h.accountManager.AddPeer(r.Context(), userAuth.AccountId, "", userAuth.UserId, newPeer, true)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	for _, rule := range req.Rules {
		protocol, portRange, err := nbtypes.ParseRuleString(rule)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		policy := &nbtypes.Policy{
			AccountID:   userAuth.AccountId,
			Description: "Temporary access policy for peer " + peer.Name,
			Name:        "Temporary access policy for peer " + peer.Name,
			Enabled:     true,
			Rules: []*nbtypes.PolicyRule{{
				Name:        "Temporary access rule",
				Description: "Temporary access rule",
				Enabled:     true,
				Action:      nbtypes.PolicyTrafficActionAccept,
				SourceResource: nbtypes.Resource{
					Type: nbtypes.ResourceTypePeer,
					ID:   peer.ID,
				},
				DestinationResource: nbtypes.Resource{
					Type: nbtypes.ResourceType(targetResource.Type.String()),
					ID:   targetResource.ID,
				},
				Bidirectional: false,
				Protocol:      protocol,
				PortRanges:    []nbtypes.RulePortRange{portRange},
			}},
		}

		_, err = h.accountManager.SavePolicy(r.Context(), userAuth.AccountId, userAuth.UserId, policy, true)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}

	resp := &api.PeerTemporaryAccessResponse{
		Id:    peer.ID,
		Name:  peer.Name,
		Rules: req.Rules,
	}

	util.WriteJSONObject(r.Context(), w, resp)
}
