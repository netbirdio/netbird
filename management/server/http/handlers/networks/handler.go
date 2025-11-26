package networks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/networks/types"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// handler is a handler that returns networks of the account
type handler struct {
	networksManager networks.Manager
	resourceManager resources.Manager
	routerManager   routers.Manager
	accountManager  account.Manager

	groupsManager groups.Manager
}

func AddEndpoints(networksManager networks.Manager, resourceManager resources.Manager, routerManager routers.Manager, groupsManager groups.Manager, accountManager account.Manager, router *mux.Router) {
	addRouterEndpoints(routerManager, router)
	addResourceEndpoints(resourceManager, groupsManager, router)

	networksHandler := newHandler(networksManager, resourceManager, routerManager, groupsManager, accountManager)
	router.HandleFunc("/networks", networksHandler.getAllNetworks).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks", networksHandler.createNetwork).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}", networksHandler.getNetwork).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}", networksHandler.updateNetwork).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}", networksHandler.deleteNetwork).Methods("DELETE", "OPTIONS")
}

func newHandler(networksManager networks.Manager, resourceManager resources.Manager, routerManager routers.Manager, groupsManager groups.Manager, accountManager account.Manager) *handler {
	return &handler{
		networksManager: networksManager,
		resourceManager: resourceManager,
		routerManager:   routerManager,
		groupsManager:   groupsManager,
		accountManager:  accountManager,
	}
}

func (h *handler) getAllNetworks(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	networks, err := h.networksManager.GetAllNetworks(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resourceIDs, err := h.resourceManager.GetAllResourceIDsInAccount(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	groups, err := h.groupsManager.GetAllGroupsMap(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routers, err := h.routerManager.GetAllRoutersInAccount(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	account, err := h.accountManager.GetAccount(r.Context(), accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, h.generateNetworkResponse(networks, routers, resourceIDs, groups, account))
}

func (h *handler) createNetwork(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.NetworkRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	network := &types.Network{}
	network.FromAPIRequest(&req)

	network.AccountID = accountID
	network, err = h.networksManager.CreateNetwork(r.Context(), userID, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	account, err := h.accountManager.GetAccount(r.Context(), accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyIDs := account.GetPoliciesAppliedInNetwork(network.ID)

	util.WriteJSONObject(r.Context(), w, network.ToAPIResponse([]string{}, []string{}, 0, policyIDs))
}

func (h *handler) getNetwork(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	networkID := vars["networkId"]
	if len(networkID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid network ID"), w)
		return
	}

	network, err := h.networksManager.GetNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routerIDs, resourceIDs, peerCount, err := h.collectIDsInNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	account, err := h.accountManager.GetAccount(r.Context(), accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyIDs := account.GetPoliciesAppliedInNetwork(networkID)

	util.WriteJSONObject(r.Context(), w, network.ToAPIResponse(routerIDs, resourceIDs, peerCount, policyIDs))
}

func (h *handler) updateNetwork(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
	vars := mux.Vars(r)
	networkID := vars["networkId"]
	if len(networkID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid network ID"), w)
		return
	}

	var req api.NetworkRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	network := &types.Network{}
	network.FromAPIRequest(&req)

	network.ID = networkID
	network.AccountID = accountID
	network, err = h.networksManager.UpdateNetwork(r.Context(), userID, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routerIDs, resourceIDs, peerCount, err := h.collectIDsInNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	account, err := h.accountManager.GetAccount(r.Context(), accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyIDs := account.GetPoliciesAppliedInNetwork(networkID)

	util.WriteJSONObject(r.Context(), w, network.ToAPIResponse(routerIDs, resourceIDs, peerCount, policyIDs))
}

func (h *handler) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
	vars := mux.Vars(r)
	networkID := vars["networkId"]
	if len(networkID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid network ID"), w)
		return
	}

	err = h.networksManager.DeleteNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func (h *handler) collectIDsInNetwork(ctx context.Context, accountID, userID, networkID string) ([]string, []string, int, error) {
	resources, err := h.resourceManager.GetAllResourcesInNetwork(ctx, accountID, userID, networkID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get resources in network: %w", err)
	}

	var resourceIDs []string
	for _, resource := range resources {
		resourceIDs = append(resourceIDs, resource.ID)
	}

	routers, err := h.routerManager.GetAllRoutersInNetwork(ctx, accountID, userID, networkID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get routers in network: %w", err)
	}

	groups, err := h.groupsManager.GetAllGroupsMap(ctx, accountID, userID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get groups: %w", err)
	}

	peerCounter := 0
	var routerIDs []string
	for _, router := range routers {
		routerIDs = append(routerIDs, router.ID)
		if router.Peer != "" {
			peerCounter++
		}
		if len(router.PeerGroups) > 0 {
			for _, groupID := range router.PeerGroups {
				group, ok := groups[groupID]
				if !ok {
					log.WithContext(ctx).Warnf("group %s not found", groupID)
					continue
				}
				peerCounter += len(group.Peers)
			}
		}
	}

	return routerIDs, resourceIDs, peerCounter, nil
}

func (h *handler) generateNetworkResponse(networks []*types.Network, routers map[string][]*routerTypes.NetworkRouter, resourceIDs map[string][]string, groups map[string]*nbtypes.Group, account *nbtypes.Account) []*api.Network {
	networkResponse := make([]*api.Network, 0, len(networks))
	for _, network := range networks {
		routerIDs, peerCounter := getRouterIDs(network, routers, groups)
		policyIDs := account.GetPoliciesAppliedInNetwork(network.ID)
		networkResponse = append(networkResponse, network.ToAPIResponse(routerIDs, resourceIDs[network.ID], peerCounter, policyIDs))
	}
	return networkResponse
}

func getRouterIDs(network *types.Network, routers map[string][]*routerTypes.NetworkRouter, groups map[string]*nbtypes.Group) ([]string, int) {
	routerIDs := []string{}
	peerCounter := 0
	for _, router := range routers[network.ID] {
		routerIDs = append(routerIDs, router.ID)
		if router.Peer != "" {
			peerCounter++
		}
		if len(router.PeerGroups) > 0 {
			for _, groupID := range router.PeerGroups {
				group, ok := groups[groupID]
				if !ok {
					continue
				}
				peerCounter += len(group.Peers)
			}
		}
	}
	return routerIDs, peerCounter
}
