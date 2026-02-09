package peers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/groups"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// Handler is a handler that returns peers of the account
type Handler struct {
	accountManager       account.Manager
	permissionsManager   permissions.Manager
	networkMapController network_map.Controller
}

func AddEndpoints(accountManager account.Manager, router *mux.Router, networkMapController network_map.Controller, permissionsManager permissions.Manager) {
	peersHandler := NewHandler(accountManager, networkMapController, permissionsManager)
	router.HandleFunc("/peers", peersHandler.GetAllPeers).Methods("GET", "OPTIONS")
	router.HandleFunc("/peers/{peerId}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
	router.HandleFunc("/peers/{peerId}/accessible-peers", peersHandler.GetAccessiblePeers).Methods("GET", "OPTIONS")
	router.HandleFunc("/peers/{peerId}/temporary-access", peersHandler.CreateTemporaryAccess).Methods("POST", "OPTIONS")
	router.HandleFunc("/peers/{peerId}/jobs", peersHandler.ListJobs).Methods("GET", "OPTIONS")
	router.HandleFunc("/peers/{peerId}/jobs", peersHandler.CreateJob).Methods("POST", "OPTIONS")
	router.HandleFunc("/peers/{peerId}/jobs/{jobId}", peersHandler.GetJob).Methods("GET", "OPTIONS")
}

// NewHandler creates a new peers Handler
func NewHandler(accountManager account.Manager, networkMapController network_map.Controller, permissionsManager permissions.Manager) *Handler {
	return &Handler{
		accountManager:       accountManager,
		networkMapController: networkMapController,
		permissionsManager:   permissionsManager,
	}
}

func (h *Handler) CreateJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	vars := mux.Vars(r)
	peerID := vars["peerId"]

	req := &api.JobRequest{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	job, err := types.NewJob(userAuth.UserId, userAuth.AccountId, peerID, req)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	if err := h.accountManager.CreatePeerJob(ctx, userAuth.AccountId, peerID, userAuth.UserId, job); err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	resp, err := toSingleJobResponse(job)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	util.WriteJSONObject(ctx, w, resp)
}

func (h *Handler) ListJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	vars := mux.Vars(r)
	peerID := vars["peerId"]

	jobs, err := h.accountManager.GetAllPeerJobs(ctx, userAuth.AccountId, userAuth.UserId, peerID)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	respBody := make([]*api.JobResponse, 0, len(jobs))
	for _, job := range jobs {
		resp, err := toSingleJobResponse(job)
		if err != nil {
			util.WriteError(ctx, err, w)
			return
		}
		respBody = append(respBody, resp)
	}

	util.WriteJSONObject(ctx, w, respBody)
}

func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	vars := mux.Vars(r)
	peerID := vars["peerId"]
	jobID := vars["jobId"]

	job, err := h.accountManager.GetPeerJobByID(ctx, userAuth.AccountId, userAuth.UserId, peerID, jobID)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	resp, err := toSingleJobResponse(job)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	util.WriteJSONObject(ctx, w, resp)
}

func (h *Handler) getPeer(ctx context.Context, accountID, peerID, userID string, w http.ResponseWriter) {
	peer, err := h.accountManager.GetPeer(ctx, accountID, peerID, userID)
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

	accountID, userID := userAuth.AccountId, userAuth.UserId

	peers, err := h.accountManager.GetPeers(r.Context(), accountID, userID, nameFilter, ipFilter)
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
	respBody := make([]*api.PeerBatch, 0, len(peers))
	for _, peer := range peers {
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

func (h *Handler) setApprovalRequiredFlag(respBody []*api.PeerBatch, validPeersMap map[string]struct{}, invalidPeersMap map[string]string) {
	for _, peer := range respBody {
		_, ok := validPeersMap[peer.Id]
		if !ok {
			peer.ApprovalRequired = true

			reason := invalidPeersMap[peer.Id]
			peer.DisapprovalReason = &reason
		}
	}
}

// GetAccessiblePeers returns a list of all peers that the specified peer can connect to within the network.
func (h *Handler) GetAccessiblePeers(w http.ResponseWriter, r *http.Request) {
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

	user, err := h.accountManager.GetUserByID(r.Context(), userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	err = h.permissionsManager.ValidateAccountAccess(r.Context(), accountID, user, false)
	if err != nil {
		util.WriteError(r.Context(), status.NewPermissionDeniedError(), w)
		return
	}

	account, err := h.accountManager.GetAccountByID(r.Context(), accountID, activity.SystemInitiator)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// If the user is regular user and does not own the peer
	// with the given peerID return an empty list
	if !user.HasAdminPower() && !user.IsServiceUser && !userAuth.IsChild {
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

	validPeers, _, err := h.accountManager.GetValidatedPeers(r.Context(), accountID)
	if err != nil {
		log.WithContext(r.Context()).Errorf("failed to list approved peers: %v", err)
		util.WriteError(r.Context(), fmt.Errorf("internal error"), w)
		return
	}

	dnsDomain := h.networkMapController.GetDNSDomain(account.Settings)

	netMap := account.GetPeerNetworkMap(r.Context(), peerID, dns.CustomZone{}, nil, validPeers, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), nil, account.GetActiveGroupUsers())

	util.WriteJSONObject(r.Context(), w, toAccessiblePeers(netMap, dnsDomain))
}

func (h *Handler) CreateTemporaryAccess(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
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

	var req api.PeerTemporaryAccessRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	newPeer := &nbpeer.Peer{}
	newPeer.FromAPITemporaryAccessRequest(&req)

	targetPeer, err := h.accountManager.GetPeer(r.Context(), userAuth.AccountId, peerID, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	peer, _, _, err := h.accountManager.AddPeer(r.Context(), userAuth.AccountId, "", userAuth.UserId, newPeer, true)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	for _, rule := range req.Rules {
		protocol, portRange, err := types.ParseRuleString(rule)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		policy := &types.Policy{
			AccountID:   userAuth.AccountId,
			Description: "Temporary access policy for peer " + peer.Name,
			Name:        "Temporary access policy for peer " + peer.Name,
			Enabled:     true,
			Rules: []*types.PolicyRule{{
				Name:        "Temporary access rule",
				Description: "Temporary access rule",
				Enabled:     true,
				Action:      types.PolicyTrafficActionAccept,
				SourceResource: types.Resource{
					Type: types.ResourceTypePeer,
					ID:   peer.ID,
				},
				DestinationResource: types.Resource{
					Type: types.ResourceTypePeer,
					ID:   targetPeer.ID,
				},
				Bidirectional: false,
				Protocol:      protocol,
				PortRanges:    []types.RulePortRange{portRange},
			}},
		}
		if protocol == types.PolicyRuleProtocolNetbirdSSH {
			policy.Rules[0].AuthorizedUser = userAuth.UserId
		}

		_, err = h.accountManager.SavePolicy(r.Context(), userAuth.AccountId, userAuth.UserId, policy, true)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}

	resp := &api.PeerTemporaryAccessResponse{
		Id:    peer.ID,
		Name:  peer.Name,
		Rules: req.Rules,
	}

	util.WriteJSONObject(r.Context(), w, resp)
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

func toSinglePeerResponse(peer *nbpeer.Peer, groupsInfo []api.GroupMinimum, dnsDomain string, approved bool, reason string) *api.Peer {
	osVersion := peer.Meta.OSVersion
	if osVersion == "" {
		osVersion = peer.Meta.Core
	}

	apiPeer := &api.Peer{
		CreatedAt:                   peer.CreatedAt,
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
		ExtraDnsLabels:              fqdnList(peer.ExtraDNSLabels, dnsDomain),
		LoginExpirationEnabled:      peer.LoginExpirationEnabled,
		LastLogin:                   peer.GetLastLogin(),
		LoginExpired:                peer.Status.LoginExpired,
		ApprovalRequired:            !approved,
		CountryCode:                 peer.Location.CountryCode,
		CityName:                    peer.Location.CityName,
		SerialNumber:                peer.Meta.SystemSerialNumber,
		InactivityExpirationEnabled: peer.InactivityExpirationEnabled,
		Ephemeral:                   peer.Ephemeral,
		LocalFlags: &api.PeerLocalFlags{
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
		},
	}

	if !approved {
		apiPeer.DisapprovalReason = &reason
	}

	return apiPeer
}

func toPeerListItemResponse(peer *nbpeer.Peer, groupsInfo []api.GroupMinimum, dnsDomain string, accessiblePeersCount int) *api.PeerBatch {
	osVersion := peer.Meta.OSVersion
	if osVersion == "" {
		osVersion = peer.Meta.Core
	}
	return &api.PeerBatch{
		CreatedAt:                   peer.CreatedAt,
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
		ExtraDnsLabels:              fqdnList(peer.ExtraDNSLabels, dnsDomain),
		LoginExpirationEnabled:      peer.LoginExpirationEnabled,
		LastLogin:                   peer.GetLastLogin(),
		LoginExpired:                peer.Status.LoginExpired,
		AccessiblePeersCount:        accessiblePeersCount,
		CountryCode:                 peer.Location.CountryCode,
		CityName:                    peer.Location.CityName,
		SerialNumber:                peer.Meta.SystemSerialNumber,
		InactivityExpirationEnabled: peer.InactivityExpirationEnabled,
		Ephemeral:                   peer.Ephemeral,
		LocalFlags: &api.PeerLocalFlags{
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
