package peers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/api/v1alpha1/groups"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Handler struct {
	accountManager       account.Manager
	permissionsManager   permissions.Manager
	networkMapController network_map.Controller
}

// NewHandler creates a new peers Handler
func NewHandler(accountManager account.Manager, networkMapController network_map.Controller, permissionsManager permissions.Manager) *Handler {
	return &Handler{
		accountManager:       accountManager,
		networkMapController: networkMapController,
		permissionsManager:   permissionsManager,
	}
}

func (h *Handler) WithEndpointsForRouter(router *mux.Router) *mux.Router {
	// router.HandleFunc("/peers", h.GetTestAllPeers).Methods("GET", "OPTIONS")
	// router.HandleFunc("/peers/{peerId}", h.HandleTestPeer).Methods("GET", "PUT", "DELETE", "OPTIONS")
	router.HandleFunc("/peers", h.GetAllPeers).Methods("GET", "OPTIONS")
	router.HandleFunc("/peers/{peerId}", h.HandlePeer).Methods("GET", "PUT", "DELETE", "OPTIONS")
	return router
}

func (h *Handler) getTestPeer(ctx context.Context, accountID, peerID, userID string, w http.ResponseWriter) {
	p := &apiv1alpha1.Peer{
		PeerMinimum: apiv1alpha1.PeerMinimum{Id: "1234", Name: "test-peer"},
	}
	util.WriteJSONObject(ctx, w, p)
}

func (h *Handler) updateTestPeer(ctx context.Context, accountID, userID, peerID string, w http.ResponseWriter, r *http.Request) {
	req := &apiv1alpha1.PeerRequest{}
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

	util.WriteJSONObject(r.Context(), w, update)
}

func (h *Handler) deleteTestPeer(ctx context.Context, accountID, userID, peerID string, w http.ResponseWriter, r *http.Request) {
	util.WriteJSONObject(ctx, w, util.EmptyObject{})
}

func (h *Handler) GetTestAllPeers(w http.ResponseWriter, r *http.Request) {
	respBody := []*apiv1alpha1.PeerBatch{
		{Peer: apiv1alpha1.Peer{PeerMinimum: apiv1alpha1.PeerMinimum{Id: "1234", Name: "test-peer"}}},
	}

	fmt.Println("page: " + r.URL.Query().Get("page"))
	fmt.Println("page_size: " + r.URL.Query().Get("page_size"))
	fmt.Println("approval_required: " + r.URL.Query().Get("approval_required") + " " + fmt.Sprintf("%v", r.URL.Query().Has("approval_required")))
	fmt.Println("os: " + r.URL.Query().Get("os"))
	fmt.Println("search: " + r.URL.Query().Get("search"))
	fmt.Println("")

	util.WriteJSONObject(r.Context(), w, respBody)

}

func (h *Handler) HandleTestPeer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	peerID := vars["peerId"]
	if len(peerID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid peer ID"), w)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		h.deleteTestPeer(r.Context(), "", "", peerID, w, r)
		return
	case http.MethodGet:
		h.getTestPeer(r.Context(), "", peerID, "", w)
		return
	case http.MethodPut:
		h.updateTestPeer(r.Context(), "", "", peerID, w, r)
		return
	default:
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "unknown METHOD"), w)
	}

}

func (h *Handler) getPeer(ctx context.Context, accountID, peerID, userID string, w http.ResponseWriter) {
	peer, err := h.accountManager.GetPeer(ctx, accountID, peerID, userID)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	if peer.ProxyMeta.Embedded {
		util.WriteError(ctx, status.Errorf(status.InvalidArgument, "not allowed to read peer"), w)
		return
	}

	settings, err := h.accountManager.GetAccountSettings(ctx, accountID, activity.SystemInitiator)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	dnsDomain := h.networkMapController.GetDNSDomain(settings)

	grps, _ := h.accountManager.GetPeerGroups(ctx, accountID, peerID)
	grpsInfoMap := groups.ToGroupsInfoMap(grps, 0)

	validPeers, invalidPeers, err := h.accountManager.GetValidatedPeers(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to list approved peers: %v", err)
		util.WriteError(ctx, fmt.Errorf("internal error"), w)
		return
	}

	_, valid := validPeers[peer.ID]
	reason := invalidPeers[peer.ID]

	util.WriteJSONObject(ctx, w, toSinglePeerResponse(peer, grpsInfoMap[peerID], dnsDomain, valid, reason))
}

func (h *Handler) updatePeer(ctx context.Context, accountID, userID, peerID string, w http.ResponseWriter, r *http.Request) {
	req := &apiv1alpha1.PeerRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	update := &nbpeer.Peer{
		ID:                          peerID,
		SSHEnabled:                  req.SshEnabled,
		Name:                        req.Name,
		LoginExpirationEnabled:      req.LoginExpirationEnabled,
		InactivityExpirationEnabled: req.InactivityExpirationEnabled,
	}

	if req.ApprovalRequired != nil {
		// todo: looks like that we reset all status property, is it right?
		update.Status = &nbpeer.PeerStatus{
			RequiresApproval: *req.ApprovalRequired,
		}
	}

	if req.Ip != nil {
		addr, err := netip.ParseAddr(*req.Ip)
		if err != nil {
			util.WriteError(ctx, status.Errorf(status.InvalidArgument, "invalid IP address %s: %v", *req.Ip, err), w)
			return
		}

		if err = h.accountManager.UpdatePeerIP(ctx, accountID, userID, peerID, addr); err != nil {
			util.WriteError(ctx, err, w)
			return
		}
	}

	if req.Ipv6 != nil {
		v6Addr, err := parseIPv6(req.Ipv6)
		if err != nil {
			util.WriteError(ctx, status.Errorf(status.InvalidArgument, "%v", err), w)
			return
		}
		if err = h.accountManager.UpdatePeerIPv6(ctx, accountID, userID, peerID, v6Addr); err != nil {
			util.WriteError(ctx, err, w)
			return
		}
	}

	peer, err := h.accountManager.UpdatePeer(ctx, accountID, userID, update)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	settings, err := h.accountManager.GetAccountSettings(ctx, accountID, activity.SystemInitiator)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	dnsDomain := h.networkMapController.GetDNSDomain(settings)

	peerGroups, err := h.accountManager.GetPeerGroups(ctx, accountID, peer.ID)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	grpsInfoMap := groups.ToGroupsInfoMap(peerGroups, 0)

	validPeers, invalidPeers, err := h.accountManager.GetValidatedPeers(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get validated peers: %v", err)
		util.WriteError(ctx, fmt.Errorf("internal error"), w)
		return
	}

	_, valid := validPeers[peer.ID]
	reason := invalidPeers[peer.ID]

	util.WriteJSONObject(r.Context(), w, toSinglePeerResponse(peer, grpsInfoMap[peerID], dnsDomain, valid, reason))
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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	nameFilter := r.URL.Query().Get("name")
	ipFilter := r.URL.Query().Get("ip")
	macFilter := r.URL.Query().Get("mac")

	accountID, userID := userAuth.AccountId, userAuth.UserId

	peers, err := h.accountManager.GetPeers(r.Context(), accountID, userID, nameFilter, ipFilter, macFilter)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	settings, err := h.accountManager.GetAccountSettings(r.Context(), accountID, activity.SystemInitiator)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	dnsDomain := h.networkMapController.GetDNSDomain(settings)

	grps, _ := h.accountManager.GetAllGroups(r.Context(), accountID, userID)

	grpsInfoMap := groups.ToGroupsInfoMap(grps, len(peers))
	respBody := make([]*apiv1alpha1.PeerBatch, 0, len(peers))
	for _, peer := range peers {
		if peer.ProxyMeta.Embedded {
			continue
		}
		respBody = append(respBody, toPeerListItemResponse(peer, grpsInfoMap[peer.ID], dnsDomain, 0))
	}

	validPeersMap, invalidPeersMap, err := h.accountManager.GetValidatedPeers(r.Context(), accountID)
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to get validated peers: %v", err)
		util.WriteError(r.Context(), fmt.Errorf("internal error"), w)
		return
	}
	h.setApprovalRequiredFlag(respBody, validPeersMap, invalidPeersMap)

	util.WriteJSONObject(r.Context(), w, respBody)
}

func (h *Handler) setApprovalRequiredFlag(respBody []*apiv1alpha1.PeerBatch, validPeersMap map[string]struct{}, invalidPeersMap map[string]string) {
	for _, peer := range respBody {
		_, ok := validPeersMap[peer.Id]
		if !ok {
			peer.ApprovalRequired = true

			reason := invalidPeersMap[peer.Id]
			peer.DisapprovalReason = &reason
		}
	}
}

func parseIPv6(s *string) (netip.Addr, error) {
	if s == nil {
		return netip.Addr{}, fmt.Errorf("IPv6 address is nil")
	}
	addr, err := netip.ParseAddr(*s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IPv6 address %s: %w", *s, err)
	}
	addr = addr.Unmap()
	if !addr.Is6() {
		return netip.Addr{}, fmt.Errorf("address %s is not IPv6", *s)
	}
	return addr, nil
}

// toAccessiblePeers resolves the twin peers in netMap back to the full account
// peers (by ID) so the API response keeps Status/Name/OS/GeoNameID, which the
// slim netmap twins intentionally don't carry.
func toAccessiblePeers(accountPeers map[string]*nbpeer.Peer, netMap *types.NetworkMap, dnsDomain string) []api.AccessiblePeer {
	accessiblePeers := make([]api.AccessiblePeer, 0, len(netMap.Peers)+len(netMap.OfflinePeers))
	appendByID := func(id string) {
		if p, ok := accountPeers[id]; ok && p != nil {
			accessiblePeers = append(accessiblePeers, peerToAccessiblePeer(p, dnsDomain))
		}
	}
	for _, p := range netMap.Peers {
		appendByID(p.ID)
	}
	for _, p := range netMap.OfflinePeers {
		appendByID(p.ID)
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
		Ipv6:        peerIPv6String(peer),
		LastSeen:    peer.Status.LastSeen,
		Name:        peer.Name,
		Os:          peer.Meta.OS,
		UserId:      peer.UserID,
	}
}

func toSinglePeerResponse(peer *nbpeer.Peer, groupsInfo []apiv1alpha1.GroupMinimum, dnsDomain string, approved bool, reason string) *apiv1alpha1.Peer {
	osVersion := peer.Meta.OSVersion
	if osVersion == "" {
		osVersion = peer.Meta.Core
	}

	apiPeer := &apiv1alpha1.Peer{
		PeerMinimum: apiv1alpha1.PeerMinimum{
			Id:   peer.ID,
			Name: peer.Name,
		},
		CreatedAt:                   peer.CreatedAt,
		Ip:                          peer.IP.String(),
		Ipv6:                        peerIPv6String(peer),
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
		ExtraDnsLabels:              fqdnList(peer.ExtraDNSLabels, dnsDomain),
		LoginExpirationEnabled:      peer.LoginExpirationEnabled,
		LastLogin:                   peer.GetLastLogin(),
		LoginExpired:                peer.Status.LoginExpired,
		ApprovalRequired:            !approved,
		CountryCode:                 apiv1alpha1.CountryCode(peer.Location.CountryCode),
		CityName:                    apiv1alpha1.CityName(peer.Location.CityName),
		SerialNumber:                peer.Meta.SystemSerialNumber,
		InactivityExpirationEnabled: peer.InactivityExpirationEnabled,
		Ephemeral:                   peer.Ephemeral,
		LocalFlags: &apiv1alpha1.PeerLocalFlags{
			BlockInbound:          &peer.Meta.Flags.BlockInbound,
			BlockLanAccess:        &peer.Meta.Flags.BlockLANAccess,
			DisableClientRoutes:   &peer.Meta.Flags.DisableClientRoutes,
			DisableDns:            &peer.Meta.Flags.DisableDNS,
			DisableFirewall:       &peer.Meta.Flags.DisableFirewall,
			DisableServerRoutes:   &peer.Meta.Flags.DisableServerRoutes,
			LazyConnectionEnabled: &peer.Meta.Flags.LazyConnectionEnabled,
			RosenpassEnabled:      &peer.Meta.Flags.RosenpassEnabled,
			RosenpassPermissive:   &peer.Meta.Flags.RosenpassPermissive,
			ServerSshAllowed:      &peer.Meta.Flags.ServerSSHAllowed,
			RemoteJobsAllowed:     &peer.Meta.Flags.RemoteJobsAllowed,
		},
	}

	if !approved {
		apiPeer.DisapprovalReason = &reason
	}

	return apiPeer
}

func toPeerListItemResponse(peer *nbpeer.Peer, groupsInfo []apiv1alpha1.GroupMinimum, dnsDomain string, accessiblePeersCount int) *apiv1alpha1.PeerBatch {
	osVersion := peer.Meta.OSVersion
	if osVersion == "" {
		osVersion = peer.Meta.Core
	}

	return &apiv1alpha1.PeerBatch{
		CreatedAt:            peer.CreatedAt,
		AccessiblePeersCount: accessiblePeersCount,
		Peer: apiv1alpha1.Peer{
			PeerMinimum: apiv1alpha1.PeerMinimum{
				Id:   peer.ID,
				Name: peer.Name,
			},
			Ip:                          peer.IP.String(),
			Ipv6:                        peerIPv6String(peer),
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
			ExtraDnsLabels:              fqdnList(peer.ExtraDNSLabels, dnsDomain),
			LoginExpirationEnabled:      peer.LoginExpirationEnabled,
			LastLogin:                   peer.GetLastLogin(),
			LoginExpired:                peer.Status.LoginExpired,
			CountryCode:                 apiv1alpha1.CountryCode(peer.Location.CountryCode),
			CityName:                    apiv1alpha1.CityName(peer.Location.CityName),
			SerialNumber:                peer.Meta.SystemSerialNumber,
			InactivityExpirationEnabled: peer.InactivityExpirationEnabled,
			Ephemeral:                   peer.Ephemeral,
			LocalFlags: &apiv1alpha1.PeerLocalFlags{
				BlockInbound:          &peer.Meta.Flags.BlockInbound,
				BlockLanAccess:        &peer.Meta.Flags.BlockLANAccess,
				DisableClientRoutes:   &peer.Meta.Flags.DisableClientRoutes,
				DisableDns:            &peer.Meta.Flags.DisableDNS,
				DisableFirewall:       &peer.Meta.Flags.DisableFirewall,
				DisableServerRoutes:   &peer.Meta.Flags.DisableServerRoutes,
				LazyConnectionEnabled: &peer.Meta.Flags.LazyConnectionEnabled,
				RosenpassEnabled:      &peer.Meta.Flags.RosenpassEnabled,
				RosenpassPermissive:   &peer.Meta.Flags.RosenpassPermissive,
				ServerSshAllowed:      &peer.Meta.Flags.ServerSSHAllowed,
				RemoteJobsAllowed:     &peer.Meta.Flags.RemoteJobsAllowed,
			},
		},
	}
}

func toSingleJobResponse(job *types.Job) (*api.JobResponse, error) {
	workload, err := job.BuildWorkloadResponse()
	if err != nil {
		return nil, err
	}

	var failed *string
	if job.FailedReason != "" {
		failed = &job.FailedReason
	}

	return &api.JobResponse{
		Id:           job.ID,
		CreatedAt:    job.CreatedAt,
		CompletedAt:  job.CompletedAt,
		TriggeredBy:  job.TriggeredBy,
		Status:       api.JobResponseStatus(job.Status),
		FailedReason: failed,
		Workload:     *workload,
	}, nil
}

func fqdn(peer *nbpeer.Peer, dnsDomain string) string {
	fqdn := peer.FQDN(dnsDomain)
	if fqdn == "" {
		return peer.DNSLabel
	} else {
		return fqdn
	}
}
func fqdnList(extraLabels []string, dnsDomain string) []string {
	fqdnList := make([]string, 0, len(extraLabels))
	for _, label := range extraLabels {
		fqdn := fmt.Sprintf("%s.%s", label, dnsDomain)
		fqdnList = append(fqdnList, fqdn)
	}
	return fqdnList
}

func peerIPv6String(peer *nbpeer.Peer) *string {
	if !peer.IPv6.IsValid() {
		return nil
	}
	s := peer.IPv6.String()
	return &s
}
