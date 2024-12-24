package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

const maxDomains = 32
const failedToConvertRoute = "failed to convert route to response: %v"

// handler is the routes handler of the account
type handler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func AddEndpoints(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	routesHandler := newHandler(accountManager, authCfg)
	router.HandleFunc("/routes", routesHandler.getAllRoutes).Methods("GET", "OPTIONS")
	router.HandleFunc("/routes", routesHandler.createRoute).Methods("POST", "OPTIONS")
	router.HandleFunc("/routes/{routeId}", routesHandler.updateRoute).Methods("PUT", "OPTIONS")
	router.HandleFunc("/routes/{routeId}", routesHandler.getRoute).Methods("GET", "OPTIONS")
	router.HandleFunc("/routes/{routeId}", routesHandler.deleteRoute).Methods("DELETE", "OPTIONS")
}

// newHandler returns a new instance of routes handler
func newHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *handler {
	return &handler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// getAllRoutes returns the list of routes for the account
func (h *handler) getAllRoutes(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routes, err := h.accountManager.ListRoutes(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	apiRoutes := make([]*api.Route, 0)
	for _, route := range routes {
		route, err := toRouteResponse(route)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.Internal, failedToConvertRoute, err), w)
			return
		}
		apiRoutes = append(apiRoutes, route)
	}

	util.WriteJSONObject(r.Context(), w, apiRoutes)
}

// createRoute handles route creation request
func (h *handler) createRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PostApiRoutesJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := h.validateRoute(req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var domains domain.List
	var networkType route.NetworkType
	var newPrefix netip.Prefix
	if req.Domains != nil {
		d, err := validateDomains(*req.Domains)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid domains: %v", err), w)
			return
		}
		domains = d
		networkType = route.DomainNetwork
	} else if req.Network != nil {
		networkType, newPrefix, err = route.ParseNetwork(*req.Network)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}

	peerId := ""
	if req.Peer != nil {
		peerId = *req.Peer
	}

	var peerGroupIds []string
	if req.PeerGroups != nil {
		peerGroupIds = *req.PeerGroups
	}

	var accessControlGroupIds []string
	if req.AccessControlGroups != nil {
		accessControlGroupIds = *req.AccessControlGroups
	}

	newRoute, err := h.accountManager.CreateRoute(r.Context(), accountID, newPrefix, networkType, domains, peerId, peerGroupIds,
		req.Description, route.NetID(req.NetworkId), req.Masquerade, req.Metric, req.Groups, accessControlGroupIds, req.Enabled, userID, req.KeepRoute)

	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routes, err := toRouteResponse(newRoute)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, failedToConvertRoute, err), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, routes)
}

func (h *handler) validateRoute(req api.PostApiRoutesJSONRequestBody) error {
	if req.Network != nil && req.Domains != nil {
		return status.Errorf(status.InvalidArgument, "only one of 'network' or 'domains' should be provided")
	}

	if req.Network == nil && req.Domains == nil {
		return status.Errorf(status.InvalidArgument, "either 'network' or 'domains' should be provided")
	}

	if req.Peer == nil && req.PeerGroups == nil {
		return status.Errorf(status.InvalidArgument, "either 'peer' or 'peer_groups' should be provided")
	}

	if req.Peer != nil && req.PeerGroups != nil {
		return status.Errorf(status.InvalidArgument, "only one of 'peer' or 'peer_groups' should be provided")
	}

	if utf8.RuneCountInString(req.NetworkId) > route.MaxNetIDChar || req.NetworkId == "" {
		return status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d characters",
			route.MaxNetIDChar)
	}

	return nil
}

// updateRoute handles update to a route identified by a given ID
func (h *handler) updateRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	routeID := vars["routeId"]
	if len(routeID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	_, err = h.accountManager.GetRoute(r.Context(), accountID, route.ID(routeID), userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PutApiRoutesRouteIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := h.validateRoute(req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	peerID := ""
	if req.Peer != nil {
		peerID = *req.Peer
	}

	newRoute := &route.Route{
		ID:          route.ID(routeID),
		NetID:       route.NetID(req.NetworkId),
		Masquerade:  req.Masquerade,
		Metric:      req.Metric,
		Description: req.Description,
		Enabled:     req.Enabled,
		Groups:      req.Groups,
		KeepRoute:   req.KeepRoute,
	}

	if req.Domains != nil {
		d, err := validateDomains(*req.Domains)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid domains: %v", err), w)
			return
		}
		newRoute.Domains = d
		newRoute.NetworkType = route.DomainNetwork
	} else if req.Network != nil {
		newRoute.NetworkType, newRoute.Network, err = route.ParseNetwork(*req.Network)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}

	if req.Peer != nil {
		newRoute.Peer = peerID
	}

	if req.PeerGroups != nil {
		newRoute.PeerGroups = *req.PeerGroups
	}

	if req.AccessControlGroups != nil {
		newRoute.AccessControlGroups = *req.AccessControlGroups
	}

	err = h.accountManager.SaveRoute(r.Context(), accountID, userID, newRoute)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routes, err := toRouteResponse(newRoute)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, failedToConvertRoute, err), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, routes)
}

// deleteRoute handles route deletion request
func (h *handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routeID := mux.Vars(r)["routeId"]
	if len(routeID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	err = h.accountManager.DeleteRoute(r.Context(), accountID, route.ID(routeID), userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// getRoute handles a route Get request identified by ID
func (h *handler) getRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routeID := mux.Vars(r)["routeId"]
	if len(routeID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	foundRoute, err := h.accountManager.GetRoute(r.Context(), accountID, route.ID(routeID), userID)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "route not found"), w)
		return
	}

	routes, err := toRouteResponse(foundRoute)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, failedToConvertRoute, err), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, routes)
}

func toRouteResponse(serverRoute *route.Route) (*api.Route, error) {
	domains, err := serverRoute.Domains.ToStringList()
	if err != nil {
		return nil, err
	}
	network := serverRoute.Network.String()
	route := &api.Route{
		Id:          string(serverRoute.ID),
		Description: serverRoute.Description,
		NetworkId:   string(serverRoute.NetID),
		Enabled:     serverRoute.Enabled,
		Peer:        &serverRoute.Peer,
		Network:     &network,
		Domains:     &domains,
		NetworkType: serverRoute.NetworkType.String(),
		Masquerade:  serverRoute.Masquerade,
		Metric:      serverRoute.Metric,
		Groups:      serverRoute.Groups,
		KeepRoute:   serverRoute.KeepRoute,
	}

	if len(serverRoute.PeerGroups) > 0 {
		route.PeerGroups = &serverRoute.PeerGroups
	}
	if len(serverRoute.AccessControlGroups) > 0 {
		route.AccessControlGroups = &serverRoute.AccessControlGroups
	}
	return route, nil
}

// validateDomains checks if each domain in the list is valid and returns a punycode-encoded DomainList.
func validateDomains(domains []string) (domain.List, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains list is empty")
	}
	if len(domains) > maxDomains {
		return nil, fmt.Errorf("domains list exceeds maximum allowed domains: %d", maxDomains)
	}

	domainRegex := regexp.MustCompile(`^(?:\*\.)?(?:(?:xn--)?[a-zA-Z0-9_](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)*(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$`)

	var domainList domain.List

	for _, d := range domains {
		d := strings.ToLower(d)

		// handles length and idna conversion
		punycode, err := domain.FromString(d)
		if err != nil {
			return domainList, fmt.Errorf("failed to convert domain to punycode: %s: %v", d, err)
		}

		if !domainRegex.MatchString(string(punycode)) {
			return domainList, fmt.Errorf("invalid domain format: %s", d)
		}

		domainList = append(domainList, punycode)
	}
	return domainList, nil
}
