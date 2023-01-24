package http

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
	"net/http"
	"unicode/utf8"
)

// Routes is the routes handler of the account
type Routes struct {
	jwtExtractor   jwtclaims.ClaimsExtractor
	accountManager server.AccountManager
	authAudience   string
}

// NewRoutes returns a new instance of Routes handler
func NewRoutes(accountManager server.AccountManager, authAudience string) *Routes {
	return &Routes{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// GetAllRoutesHandler returns the list of routes for the account
func (h *Routes) GetAllRoutesHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	routes, err := h.accountManager.ListRoutes(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	apiRoutes := make([]*api.Route, 0)
	for _, r := range routes {
		apiRoutes = append(apiRoutes, toRouteResponse(account, r))
	}

	util.WriteJSONObject(w, apiRoutes)
}

// CreateRouteHandler handles route creation request
func (h *Routes) CreateRouteHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PostApiRoutesJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	_, newPrefix, err := route.ParseNetwork(req.Network)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	if utf8.RuneCountInString(req.NetworkId) > route.MaxNetIDChar || req.NetworkId == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d",
			route.MaxNetIDChar), w)
		return
	}

	newRoute, err := h.accountManager.CreateRoute(account.Id, newPrefix.String(), req.Peer, req.Description, req.NetworkId, req.Masquerade, req.Metric, req.Groups, req.Enabled, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRouteResponse(account, newRoute)

	util.WriteJSONObject(w, &resp)
}

// UpdateRouteHandler handles update to a route identified by a given ID
func (h *Routes) UpdateRouteHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	routeID := vars["id"]
	if len(routeID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	_, err = h.accountManager.GetRoute(account.Id, routeID, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PutApiRoutesIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	prefixType, newPrefix, err := route.ParseNetwork(req.Network)
	if err != nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "couldn't parse update prefix %s for route ID %s",
			req.Network, routeID), w)
		return
	}

	peerKey := req.Peer
	if req.Peer != "" {
		peer, err := h.accountManager.GetPeerByIP(account.Id, req.Peer)
		if err != nil {
			util.WriteError(err, w)
			return
		}
		peerKey = peer.Key
	}

	if utf8.RuneCountInString(req.NetworkId) > route.MaxNetIDChar || req.NetworkId == "" {
		util.WriteError(status.Errorf(status.InvalidArgument,
			"identifier should be between 1 and %d", route.MaxNetIDChar), w)
		return
	}

	newRoute := &route.Route{
		ID:          routeID,
		Network:     newPrefix,
		NetID:       req.NetworkId,
		NetworkType: prefixType,
		Masquerade:  req.Masquerade,
		Peer:        peerKey,
		Metric:      req.Metric,
		Description: req.Description,
		Enabled:     req.Enabled,
		Groups:      req.Groups,
	}

	err = h.accountManager.SaveRoute(account.Id, newRoute)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRouteResponse(account, newRoute)

	util.WriteJSONObject(w, &resp)
}

// PatchRouteHandler handles patch updates to a route identified by a given ID
func (h *Routes) PatchRouteHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	routeID := vars["id"]
	if len(routeID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	_, err = h.accountManager.GetRoute(account.Id, routeID, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PatchApiRoutesIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if len(req) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "no patch instruction received"), w)
		return
	}

	var operations []server.RouteUpdateOperation

	for _, patch := range req {
		switch patch.Path {
		case api.RoutePatchOperationPathNetwork:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"network field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRouteNetwork,
				Values: patch.Value,
			})
		case api.RoutePatchOperationPathDescription:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"description field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRouteDescription,
				Values: patch.Value,
			})
		case api.RoutePatchOperationPathNetworkId:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"network Identifier field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRouteNetworkIdentifier,
				Values: patch.Value,
			})
		case api.RoutePatchOperationPathPeer:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"peer field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			if len(patch.Value) > 1 {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"value field only accepts 1 value, got %d", len(patch.Value)), w)
				return
			}
			peerValue := patch.Value
			if patch.Value[0] != "" {
				peer, err := h.accountManager.GetPeerByIP(account.Id, patch.Value[0])
				if err != nil {
					util.WriteError(err, w)
					return
				}
				peerValue = []string{peer.Key}
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRoutePeer,
				Values: peerValue,
			})
		case api.RoutePatchOperationPathMetric:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"metric field only accepts replace operation, got %s", patch.Op), w)

				return
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRouteMetric,
				Values: patch.Value,
			})
		case api.RoutePatchOperationPathMasquerade:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"masquerade field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRouteMasquerade,
				Values: patch.Value,
			})
		case api.RoutePatchOperationPathEnabled:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"enabled field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRouteEnabled,
				Values: patch.Value,
			})
		case api.RoutePatchOperationPathGroups:
			if patch.Op != api.RoutePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"groups field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RouteUpdateOperation{
				Type:   server.UpdateRouteGroups,
				Values: patch.Value,
			})
		default:
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid patch path"), w)
			return
		}
	}

	route, err := h.accountManager.UpdateRoute(account.Id, routeID, operations)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRouteResponse(account, route)

	util.WriteJSONObject(w, &resp)
}

// DeleteRouteHandler handles route deletion request
func (h *Routes) DeleteRouteHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	routeID := mux.Vars(r)["id"]
	if len(routeID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	err = h.accountManager.DeleteRoute(account.Id, routeID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, "")
}

// GetRouteHandler handles a route Get request identified by ID
func (h *Routes) GetRouteHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	routeID := mux.Vars(r)["id"]
	if len(routeID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	foundRoute, err := h.accountManager.GetRoute(account.Id, routeID, user.Id)
	if err != nil {
		util.WriteError(status.Errorf(status.NotFound, "route not found"), w)
		return
	}

	util.WriteJSONObject(w, toRouteResponse(account, foundRoute))
}

func toRouteResponse(account *server.Account, serverRoute *route.Route) *api.Route {
	var peerIP string
	if serverRoute.Peer != "" {
		peer, found := account.Peers[serverRoute.Peer]
		if !found {
			panic("peer ID not found")
		}
		peerIP = peer.IP.String()
	}

	return &api.Route{
		Id:          serverRoute.ID,
		Description: serverRoute.Description,
		NetworkId:   serverRoute.NetID,
		Enabled:     serverRoute.Enabled,
		Peer:        peerIP,
		Network:     serverRoute.Network.String(),
		NetworkType: serverRoute.NetworkType.String(),
		Masquerade:  serverRoute.Masquerade,
		Metric:      serverRoute.Metric,
		Groups:      serverRoute.Groups,
	}
}
