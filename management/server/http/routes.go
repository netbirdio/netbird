package http

import (
	"encoding/json"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// Routes is a handler that returns rules of the account
type Routes struct {
	jwtExtractor   jwtclaims.ClaimsExtractor
	accountManager server.AccountManager
	authAudience   string
}

func NewRoutes(accountManager server.AccountManager, authAudience string) *Routes {
	return &Routes{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// GetAllRulesHandler list for the account
func (h *Routes) GetAllRoutesHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	routes, err := h.accountManager.ListRoutes(account.Id)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}
	apiRoutes := make([]*api.Route, 0)
	for _, r := range routes {
		apiRoutes = append(apiRoutes, toRouteResponse(account, r))
	}

	writeJSONObject(w, apiRoutes)
}

// CreateRouteHandler handles rule creation request
func (h *Routes) CreateRouteHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var req api.PostApiRoutesJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Debugf("%#v", req)

	peer, _ := h.accountManager.GetPeerByIP(account.Id, req.Peer)

	newRoute, err := h.accountManager.CreateRoute(account.Id, req.Prefix, peer.Key, req.Description, req.Masquerade, req.Metric, req.Enabled)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	resp := toRouteResponse(account, newRoute)

	writeJSONObject(w, &resp)
}

func toRouteResponse(_ *server.Account, serverRoute *route.Route) *api.Route {
	return &api.Route{
		Id:          serverRoute.ID,
		Description: serverRoute.Description,
		Enabled:     serverRoute.Enabled,
		Peer:        serverRoute.Peer,
		Prefix:      serverRoute.Prefix.String(),
		PrefixType:  serverRoute.PrefixType.String(),
		Masquerade:  serverRoute.Masquerade,
		Metric:      serverRoute.Metric,
	}
}
