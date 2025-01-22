package peers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

// Handler is a handler that returns peers of the account
type Handler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func AddEndpoints(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	peersHandler := NewHandler(accountManager, authCfg)
	router.HandleFunc("/peers", peersHandler.GetAllPeers).Methods("GET", "OPTIONS")
	router.HandleFunc("/peers/{peerId}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
	router.HandleFunc("/peers/{peerId}/accessible-peers", peersHandler.GetAccessiblePeers).Methods("GET", "OPTIONS")
}

// NewHandler creates a new peers Handler
func NewHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *Handler {
	return &Handler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

func (h *Handler) checkPeerStatus(peer *nbpeer.Peer) (*nbpeer.Peer, error) {
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

func (h *Handler) getPeer(ctx context.Context, accountID, peerID, userID string, w http.ResponseWriter) {
	peer, err := h.accountManager.GetPeer(ctx, accountID, peerID, userID)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	peerToReturn, err := h.checkPeerStatus(peer)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	dnsDomain := h.accountManager.GetDNSDomain()

	grps, _ := h.accountManager.GetPeerGroups(ctx, accountID, peerID)
	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	validPeers, err := h.accountManager.GetValidatedPeers(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to list approved peers: %v", err)
		util.WriteError(ctx, fmt.Errorf("internal error"), w)
		return
	}

	_, valid := validPeers[peer.ID]
	util.WriteJSONObject(ctx, w, toSinglePeerResponse(peerToReturn, grpsInfoMap[peerID], dnsDomain, valid))
}

func (h *Handler) updatePeer(ctx context.Context, accountID, userID, peerID string, w http.ResponseWriter, r *http.Request) {
	req := &api.PeerRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	update := &nbpeer.Peer{
		ID:                     peerID,
		SSHEnabled:             req.SshEnabled,
		Name:                   req.Name,
		LoginExpirationEnabled: req.LoginExpirationEnabled,

		InactivityExpirationEnabled: req.InactivityExpirationEnabled,
	}

	if req.ApprovalRequired != nil {
		// todo: looks like that we reset all status property, is it right?
		update.Status = &nbpeer.PeerStatus{
			RequiresApproval: *req.ApprovalRequired,
		}
	}

	peer, err := h.accountManager.UpdatePeer(ctx, accountID, userID, update)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	dnsDomain := h.accountManager.GetDNSDomain()

	peerGroups, err := h.accountManager.GetPeerGroups(ctx, accountID, peer.ID)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(peerGroups, 0)

	validPeers, err := h.accountManager.GetValidatedPeers(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to list appreoved peers: %v", err)
		util.WriteError(ctx, fmt.Errorf("internal error"), w)
		return
	}

	_, valid := validPeers[peer.ID]

	util.WriteJSONObject(r.Context(), w, toSinglePeerResponse(peer, grpsInfoMap[peerID], dnsDomain, valid))
}

func (h *Handler) deletePeer(ctx context.Context, accountID, userID string, peerID string, w http.ResponseWriter) {
	err := h.accountManager.DeletePeer(ctx, accountID, peerID, userID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer: %v", err)
		util.WriteError(ctx, err, w)
		return
	}
	util.WriteJSONObject(ctx, w, util.EmptyObject{})
}

// HandlePeer handles all peer requests for GET, PUT and DELETE operations
func (h *Handler) HandlePeer(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	vars := mux.Vars(r)
	peerID := vars["peerId"]
	if len(peerID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid peer ID"), w)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		h.deletePeer(r.Context(), accountID, userID, peerID, w)
		return
	case http.MethodGet:
		h.getPeer(r.Context(), accountID, peerID, userID, w)
		return
	case http.MethodPut:
		h.updatePeer(r.Context(), accountID, userID, peerID, w, r)
		return
	default:
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "unknown METHOD"), w)
	}
}

// GetAllPeers returns a list of all peers associated with a provided account
func (h *Handler) GetAllPeers(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	peers, err := h.accountManager.GetPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	dnsDomain := h.accountManager.GetDNSDomain()

	grps, _ := h.accountManager.GetAllGroups(r.Context(), accountID, userID)

	grpsInfoMap := groups.ToGroupsInfoMap(grps, len(peers))
	respBody := make([]*api.PeerBatch, 0, len(peers))
	for _, peer := range peers {
		peerToReturn, err := h.checkPeerStatus(peer)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}

		respBody = append(respBody, toPeerListItemResponse(peerToReturn, grpsInfoMap[peer.ID], dnsDomain, 0))
	}

	validPeersMap, err := h.accountManager.GetValidatedPeers(r.Context(), accountID)
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to list appreoved peers: %v", err)
		util.WriteError(r.Context(), fmt.Errorf("internal error"), w)
		return
	}
	h.setApprovalRequiredFlag(respBody, validPeersMap)

	util.WriteJSONObject(r.Context(), w, respBody)
}

func (h *Handler) setApprovalRequiredFlag(respBody []*api.PeerBatch, approvedPeersMap map[string]struct{}) {
	for _, peer := range respBody {
		_, ok := approvedPeersMap[peer.Id]
		if !ok {
			peer.ApprovalRequired = true
		}
	}
}

// GetAccessiblePeers returns a list of all peers that the specified peer can connect to within the network.
func (h *Handler) GetAccessiblePeers(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	peerID := vars["peerId"]
	if len(peerID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid peer ID"), w)
		return
	}

	account, err := h.accountManager.GetAccountByID(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := account.FindUser(userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// If the user is regular user and does not own the peer
	// with the given peerID return an empty list
	if !user.HasAdminPower() && !user.IsServiceUser {
		peer, ok := account.Peers[peerID]
		if !ok {
			util.WriteError(r.Context(), status.Errorf(status.NotFound, "peer not found"), w)
			return
		}

		if peer.UserID != user.Id {
			util.WriteJSONObject(r.Context(), w, []api.AccessiblePeer{})
			return
		}
	}

	validPeers, err := h.accountManager.GetValidatedPeers(r.Context(), accountID)
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to list approved peers: %v", err)
		util.WriteError(r.Context(), fmt.Errorf("internal error"), w)
		return
	}

	dnsDomain := h.accountManager.GetDNSDomain()

	customZone := account.GetPeersCustomZone(r.Context(), dnsDomain)
	netMap := account.GetPeerNetworkMap(r.Context(), peerID, customZone, validPeers, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), nil)

	util.WriteJSONObject(r.Context(), w, toAccessiblePeers(netMap, dnsDomain))
}

func toAccessiblePeers(netMap *types.NetworkMap, dnsDomain string) []api.AccessiblePeer {
	accessiblePeers := make([]api.AccessiblePeer, 0, len(netMap.Peers)+len(netMap.OfflinePeers))
	for _, p := range netMap.Peers {
		accessiblePeers = append(accessiblePeers, peerToAccessiblePeer(p, dnsDomain))
	}

	for _, p := range netMap.OfflinePeers {
		accessiblePeers = append(accessiblePeers, peerToAccessiblePeer(p, dnsDomain))
	}

	return accessiblePeers
}

func peerToAccessiblePeer(peer *nbpeer.Peer, dnsDomain string) api.AccessiblePeer {
	return api.AccessiblePeer{
		CityName:    peer.Location.CityName,
		Connected:   peer.Status.Connected,
		CountryCode: peer.Location.CountryCode,
		DnsLabel:    fqdn(peer, dnsDomain),
		GeonameId:   int(peer.Location.GeoNameID),
		Id:          peer.ID,
		Ip:          peer.IP.String(),
		LastSeen:    peer.Status.LastSeen,
		Name:        peer.Name,
		Os:          peer.Meta.OS,
		UserId:      peer.UserID,
	}
}

func toSinglePeerResponse(peer *nbpeer.Peer, groupsInfo []api.GroupMinimum, dnsDomain string, approved bool) *api.Peer {
	osVersion := peer.Meta.OSVersion
	if osVersion == "" {
		osVersion = peer.Meta.Core
	}

	return &api.Peer{
		Id:                          peer.ID,
		Name:                        peer.Name,
		Ip:                          peer.IP.String(),
		ConnectionIp:                peer.Location.ConnectionIP.String(),
		Connected:                   peer.Status.Connected,
		LastSeen:                    peer.Status.LastSeen,
		Os:                          fmt.Sprintf("%s %s", peer.Meta.OS, osVersion),
		KernelVersion:               peer.Meta.KernelVersion,
		GeonameId:                   int(peer.Location.GeoNameID),
		Version:                     peer.Meta.WtVersion,
		Groups:                      groupsInfo,
		SshEnabled:                  peer.SSHEnabled,
		Hostname:                    peer.Meta.Hostname,
		UserId:                      peer.UserID,
		UiVersion:                   peer.Meta.UIVersion,
		DnsLabel:                    fqdn(peer, dnsDomain),
		LoginExpirationEnabled:      peer.LoginExpirationEnabled,
		LastLogin:                   peer.GetLastLogin(),
		LoginExpired:                peer.Status.LoginExpired,
		ApprovalRequired:            !approved,
		CountryCode:                 peer.Location.CountryCode,
		CityName:                    peer.Location.CityName,
		SerialNumber:                peer.Meta.SystemSerialNumber,
		InactivityExpirationEnabled: peer.InactivityExpirationEnabled,
	}
}

func toPeerListItemResponse(peer *nbpeer.Peer, groupsInfo []api.GroupMinimum, dnsDomain string, accessiblePeersCount int) *api.PeerBatch {
	osVersion := peer.Meta.OSVersion
	if osVersion == "" {
		osVersion = peer.Meta.Core
	}

	return &api.PeerBatch{
		Id:                     peer.ID,
		Name:                   peer.Name,
		Ip:                     peer.IP.String(),
		ConnectionIp:           peer.Location.ConnectionIP.String(),
		Connected:              peer.Status.Connected,
		LastSeen:               peer.Status.LastSeen,
		Os:                     fmt.Sprintf("%s %s", peer.Meta.OS, osVersion),
		KernelVersion:          peer.Meta.KernelVersion,
		GeonameId:              int(peer.Location.GeoNameID),
		Version:                peer.Meta.WtVersion,
		Groups:                 groupsInfo,
		SshEnabled:             peer.SSHEnabled,
		Hostname:               peer.Meta.Hostname,
		UserId:                 peer.UserID,
		UiVersion:              peer.Meta.UIVersion,
		DnsLabel:               fqdn(peer, dnsDomain),
		LoginExpirationEnabled: peer.LoginExpirationEnabled,
		LastLogin:              peer.GetLastLogin(),
		LoginExpired:           peer.Status.LoginExpired,
		AccessiblePeersCount:   accessiblePeersCount,
		CountryCode:            peer.Location.CountryCode,
		CityName:               peer.Location.CityName,
		SerialNumber:           peer.Meta.SystemSerialNumber,

		InactivityExpirationEnabled: peer.InactivityExpirationEnabled,
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
