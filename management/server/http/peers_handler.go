package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// PeersHandler is a handler that returns peers of the account
type PeersHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewPeersHandler creates a new PeersHandler HTTP handler
func NewPeersHandler(accountManager server.AccountManager, authCfg AuthCfg) *PeersHandler {
	return &PeersHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

func (h *PeersHandler) getPeer(account *server.Account, peerID, userID string, w http.ResponseWriter) {
	peer, err := h.accountManager.GetPeer(account.Id, peerID, userID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPeerResponse(peer, account, h.accountManager.GetDNSDomain()))
}

func (h *PeersHandler) updatePeer(account *server.Account, user *server.User, peerID string, w http.ResponseWriter, r *http.Request) {
	req := &api.PutApiPeersIdJSONBody{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	update := &server.Peer{ID: peerID, SSHEnabled: req.SshEnabled, Name: req.Name,
		LoginExpirationEnabled: req.LoginExpirationEnabled}
	peer, err := h.accountManager.UpdatePeer(account.Id, user.Id, update)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	dnsDomain := h.accountManager.GetDNSDomain()
	util.WriteJSONObject(w, toPeerResponse(peer, account, dnsDomain))
}

func (h *PeersHandler) deletePeer(accountID, userID string, peerID string, w http.ResponseWriter) {
	_, err := h.accountManager.DeletePeer(accountID, peerID, userID)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, emptyObject{})
}

// HandlePeer handles all peer requests for GET, PUT and DELETE operations
func (h *PeersHandler) HandlePeer(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	vars := mux.Vars(r)
	peerID := vars["id"]
	if len(peerID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid peer ID"), w)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		h.deletePeer(account.Id, user.Id, peerID, w)
		return
	case http.MethodPut:
		h.updatePeer(account, user, peerID, w, r)
		return
	case http.MethodGet:
		h.getPeer(account, peerID, user.Id, w)
		return
	default:
		util.WriteError(status.Errorf(status.NotFound, "unknown METHOD"), w)
	}
}

// GetAllPeers returns a list of all peers associated with a provided account
func (h *PeersHandler) GetAllPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims := h.claimsExtractor.FromRequestContext(r)
		account, user, err := h.accountManager.GetAccountFromToken(claims)
		if err != nil {
			util.WriteError(err, w)
			return
		}

		peers, err := h.accountManager.GetPeers(account.Id, user.Id)
		if err != nil {
			util.WriteError(err, w)
			return
		}

		dnsDomain := h.accountManager.GetDNSDomain()

		respBody := []*api.Peer{}
		for _, peer := range peers {
			respBody = append(respBody, toPeerResponse(peer, account, dnsDomain))
		}
		util.WriteJSONObject(w, respBody)
		return
	default:
		util.WriteError(status.Errorf(status.NotFound, "unknown METHOD"), w)
	}
}

func toPeerResponse(peer *server.Peer, account *server.Account, dnsDomain string) *api.Peer {
	var groupsInfo []api.GroupMinimum
	groupsChecked := make(map[string]struct{})
	for _, group := range account.Groups {
		_, ok := groupsChecked[group.ID]
		if ok {
			continue
		}
		groupsChecked[group.ID] = struct{}{}
		for _, pk := range group.Peers {
			if pk == peer.ID {
				info := api.GroupMinimum{
					Id:         group.ID,
					Name:       group.Name,
					PeersCount: len(group.Peers),
				}
				groupsInfo = append(groupsInfo, info)
				break
			}
		}
	}

	fqdn := peer.FQDN(dnsDomain)
	if fqdn == "" {
		fqdn = peer.DNSLabel
	}

	return &api.Peer{
		Id:                     peer.ID,
		Name:                   peer.Name,
		Ip:                     peer.IP.String(),
		Connected:              peer.Status.Connected,
		LastSeen:               peer.Status.LastSeen,
		Os:                     fmt.Sprintf("%s %s", peer.Meta.OS, peer.Meta.Core),
		Version:                peer.Meta.WtVersion,
		Groups:                 groupsInfo,
		SshEnabled:             peer.SSHEnabled,
		Hostname:               peer.Meta.Hostname,
		UserId:                 &peer.UserID,
		UiVersion:              &peer.Meta.UIVersion,
		DnsLabel:               fqdn,
		LoginExpirationEnabled: peer.LoginExpirationEnabled,
		LastLogin:              peer.LastLogin,
		LoginExpired:           peer.Status.LoginExpired,
	}
}
