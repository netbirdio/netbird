package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager exitnodes.Manager
}

// RegisterEndpoints registers the exit node API endpoints on router.
func RegisterEndpoints(router *mux.Router, manager exitnodes.Manager) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/exit-nodes", h.getAllExitNodes).Methods("GET", "OPTIONS")
	router.HandleFunc("/exit-nodes", h.createExitNode).Methods("POST", "OPTIONS")
	router.HandleFunc("/exit-nodes/{exitNodeId}", h.getExitNode).Methods("GET", "OPTIONS")
	router.HandleFunc("/exit-nodes/{exitNodeId}", h.updateExitNode).Methods("PUT", "OPTIONS")
	router.HandleFunc("/exit-nodes/{exitNodeId}", h.deleteExitNode).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllExitNodes(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	nodes, err := h.manager.GetAllExitNodes(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponses(nodes))
}

func (h *handler) createExitNode(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PostApiExitNodesJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	node := new(exitnodes.ExitNode)
	node.FromAPIRequest(&req)

	created, err := h.manager.CreateExitNode(r.Context(), userAuth.AccountId, userAuth.UserId, node)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse())
}

func (h *handler) getExitNode(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	exitNodeID, ok := exitNodeIDFromRequest(w, r)
	if !ok {
		return
	}

	node, err := h.manager.GetExitNode(r.Context(), userAuth.AccountId, userAuth.UserId, exitNodeID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, node.ToAPIResponse())
}

func (h *handler) updateExitNode(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	exitNodeID, ok := exitNodeIDFromRequest(w, r)
	if !ok {
		return
	}

	var req api.PutApiExitNodesExitNodeIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	node := new(exitnodes.ExitNode)
	node.FromAPIRequest(&req)
	node.ID = exitNodeID

	updated, err := h.manager.UpdateExitNode(r.Context(), userAuth.AccountId, userAuth.UserId, node)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse())
}

func (h *handler) deleteExitNode(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	exitNodeID, ok := exitNodeIDFromRequest(w, r)
	if !ok {
		return
	}

	if err := h.manager.DeleteExitNode(r.Context(), userAuth.AccountId, userAuth.UserId, exitNodeID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func exitNodeIDFromRequest(w http.ResponseWriter, r *http.Request) (exitnodes.ID, bool) {
	exitNodeID := mux.Vars(r)["exitNodeId"]
	if exitNodeID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "exit node ID is required"), w)
		return "", false
	}
	return exitnodes.ID(exitNodeID), true
}

func toAPIResponses(nodes []*exitnodes.ExitNode) []*api.ExitNode {
	result := make([]*api.ExitNode, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, node.ToAPIResponse())
	}
	return result
}
