package http

import (
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// Nameservers is the nameserver group handler of the account
type Nameservers struct {
	jwtExtractor   jwtclaims.ClaimsExtractor
	accountManager server.AccountManager
	authAudience   string
}

// NewNameservers returns a new instance of Nameservers handler
func NewNameservers(accountManager server.AccountManager, authAudience string) *Nameservers {
	return &Nameservers{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// GetAllNameserversHandler returns the list of nameserver groups for the account
func (h *Nameservers) GetAllNameserversHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	nsGroups, err := h.accountManager.ListNameServerGroups(account.Id)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}
	apiNameservers := make([]*api.NameserverGroup, 0)
	for _, r := range nsGroups {
		apiNameservers = append(apiNameservers, toNameserverGroupResponse(r))
	}

	writeJSONObject(w, apiNameservers)
}

// CreateNameserverGroupHandler handles route creation request
func (h *Nameservers) CreateNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {
}

// UpdateNameserverGroupHandler handles update to a route identified by a given ID
func (h *Nameservers) UpdateNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {
}

// PatchNameserverGroupHandler handles patch updates to a route identified by a given ID
func (h *Nameservers) PatchNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {

}

// DeleteNameserverGroupHandler handles route deletion request
func (h *Nameservers) DeleteNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {

}

// GetNameserverGroupHandler handles a route Get request identified by ID
func (h *Nameservers) GetNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {

}

func toNameserverGroupResponse(serverRoute *nbdns.NameServerGroup) *api.NameserverGroup {
	var nsList []api.Nameserver
	for _, ns := range serverRoute.NameServers {
		apiNS := api.Nameserver{
			Ip:     ns.IP.String(),
			NsType: api.NameserverNsType(ns.NSType.String()),
			Port:   ns.Port,
		}
		nsList = append(nsList, apiNS)
	}

	return &api.NameserverGroup{
		Id:          serverRoute.ID,
		Description: serverRoute.Description,
		Groups:      serverRoute.Groups,
		Nameservers: nsList,
		Enabled:     serverRoute.Enabled,
	}
}
