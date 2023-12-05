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
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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

func (h *PeersHandler) checkPeerStatus(peer *nbpeer.Peer) (*nbpeer.Peer, error) {
	peerToReturn := peer.Copy()
	if peer.Status.Connected {
		// Although we have online status in store we do not yet have an updated channel so have to show it as disconnected
		// This may happen after server restart when not all peers are yet connected
		if !h.accountManager.HasConnectedChannel(peer.ID) {
			peerToReturn.Status.Connected = false
		}
	}

	return peerToReturn, nil
}

func (h *PeersHandler) getPeer(account *server.Account, peerID, userID string, w http.ResponseWriter) {
	peer, err := h.accountManager.GetPeer(account.Id, peerID, userID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	peerToReturn, err := h.checkPeerStatus(peer)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	dnsDomain := h.accountManager.GetDNSDomain()

	groupsInfo := toGroupsInfo(account.Groups, peer.ID)

	netMap := account.GetPeerNetworkMap(peerID, h.accountManager.GetDNSDomain())
	accessiblePeers := toAccessiblePeers(netMap, dnsDomain)

	util.WriteJSONObject(w, toSinglePeerResponse(peerToReturn, groupsInfo, dnsDomain, accessiblePeers))
}

func (h *PeersHandler) updatePeer(account *server.Account, user *server.User, peerID string, w http.ResponseWriter, r *http.Request) {
	req := &api.PeerRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	update := &nbpeer.Peer{ID: peerID, SSHEnabled: req.SshEnabled, Name: req.Name,
		LoginExpirationEnabled: req.LoginExpirationEnabled}

	if req.ApprovalRequired != nil {
		update.Status = &nbpeer.PeerStatus{RequiresApproval: *req.ApprovalRequired}
	}

	peer, err := h.accountManager.UpdatePeer(account.Id, user.Id, update)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	dnsDomain := h.accountManager.GetDNSDomain()

	groupMinimumInfo := toGroupsInfo(account.Groups, peer.ID)

	netMap := account.GetPeerNetworkMap(peerID, h.accountManager.GetDNSDomain())
	accessiblePeers := toAccessiblePeers(netMap, dnsDomain)

	util.WriteJSONObject(w, toSinglePeerResponse(peer, groupMinimumInfo, dnsDomain, accessiblePeers))
}

func (h *PeersHandler) deletePeer(accountID, userID string, peerID string, w http.ResponseWriter) {
	err := h.accountManager.DeletePeer(accountID, peerID, userID)
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
	peerID := vars["peerId"]
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

		respBody := make([]*api.PeerBatch, 0, len(peers))
		for _, peer := range peers {
			peerToReturn, err := h.checkPeerStatus(peer)
			if err != nil {
				util.WriteError(err, w)
				return
			}
			groupMinimumInfo := toGroupsInfo(account.Groups, peer.ID)

			accessiblePeerNumbers := h.accessiblePeersNumber(account, peer.ID)

			respBody = append(respBody, toPeerListItemResponse(peerToReturn, groupMinimumInfo, dnsDomain, accessiblePeerNumbers))
		}
		util.WriteJSONObject(w, respBody)
		return
	default:
		util.WriteError(status.Errorf(status.NotFound, "unknown METHOD"), w)
	}
}

func (h *PeersHandler) accessiblePeersNumber(account *server.Account, peerID string) int {
	netMap := account.GetPeerNetworkMap(peerID, h.accountManager.GetDNSDomain())
	return len(netMap.Peers) + len(netMap.OfflinePeers)
}

func toAccessiblePeers(netMap *server.NetworkMap, dnsDomain string) []api.AccessiblePeer {
	accessiblePeers := make([]api.AccessiblePeer, 0, len(netMap.Peers)+len(netMap.OfflinePeers))
	for _, p := range netMap.Peers {
		ap := api.AccessiblePeer{
			Id:       p.ID,
			Name:     p.Name,
			Ip:       p.IP.String(),
			DnsLabel: fqdn(p, dnsDomain),
			UserId:   p.UserID,
		}
		accessiblePeers = append(accessiblePeers, ap)
	}

	for _, p := range netMap.OfflinePeers {
		ap := api.AccessiblePeer{
			Id:       p.ID,
			Name:     p.Name,
			Ip:       p.IP.String(),
			DnsLabel: fqdn(p, dnsDomain),
			UserId:   p.UserID,
		}
		accessiblePeers = append(accessiblePeers, ap)
	}
	return accessiblePeers
}

func toGroupsInfo(groups map[string]*server.Group, peerID string) []api.GroupMinimum {
	var groupsInfo []api.GroupMinimum
	groupsChecked := make(map[string]struct{})
	for _, group := range groups {
		_, ok := groupsChecked[group.ID]
		if ok {
			continue
		}
		groupsChecked[group.ID] = struct{}{}
		for _, pk := range group.Peers {
			if pk == peerID {
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
	return groupsInfo
}

func toSinglePeerResponse(peer *nbpeer.Peer, groupsInfo []api.GroupMinimum, dnsDomain string, accessiblePeer []api.AccessiblePeer) *api.Peer {
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
		DnsLabel:               fqdn(peer, dnsDomain),
		LoginExpirationEnabled: peer.LoginExpirationEnabled,
		LastLogin:              peer.LastLogin,
		LoginExpired:           peer.Status.LoginExpired,
		AccessiblePeers:        accessiblePeer,
		ApprovalRequired:       &peer.Status.RequiresApproval,
	}
}

func toPeerListItemResponse(peer *nbpeer.Peer, groupsInfo []api.GroupMinimum, dnsDomain string, accessiblePeersCount int) *api.PeerBatch {
	return &api.PeerBatch{
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
		DnsLabel:               fqdn(peer, dnsDomain),
		LoginExpirationEnabled: peer.LoginExpirationEnabled,
		LastLogin:              peer.LastLogin,
		LoginExpired:           peer.Status.LoginExpired,
		AccessiblePeersCount:   accessiblePeersCount,
		ApprovalRequired:       &peer.Status.RequiresApproval,
	}
}

func fqdn(peer *nbpeer.Peer, dnsDomain string) string {
	fqdn := peer.FQDN(dnsDomain)
	if fqdn == "" {
		return peer.DNSLabel
	} else {
		return fqdn
	}
}
