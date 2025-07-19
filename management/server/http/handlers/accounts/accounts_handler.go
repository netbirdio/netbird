package accounts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	// PeerBufferPercentage is the percentage of peers to add as buffer for network range calculations
	PeerBufferPercentage = 0.5
	// MinRequiredAddresses is the minimum number of addresses required in a network range
	MinRequiredAddresses = 10
	// MinNetworkBits is the minimum prefix length for IPv4 network ranges (e.g., /29 gives 8 addresses, /28 gives 16)
	MinNetworkBitsIPv4 = 28
	// MinNetworkBitsIPv6 is the minimum prefix length for IPv6 network ranges
	MinNetworkBitsIPv6 = 120
)

// handler is a handler that handles the server.Account HTTP endpoints
type handler struct {
	accountManager  account.Manager
	settingsManager settings.Manager
}

func AddEndpoints(accountManager account.Manager, settingsManager settings.Manager, router *mux.Router) {
	accountsHandler := newHandler(accountManager, settingsManager)
	router.HandleFunc("/accounts/{accountId}", accountsHandler.updateAccount).Methods("PUT", "OPTIONS")
	router.HandleFunc("/accounts/{accountId}", accountsHandler.deleteAccount).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/accounts", accountsHandler.getAllAccounts).Methods("GET", "OPTIONS")
}

// newHandler creates a new handler HTTP handler
func newHandler(accountManager account.Manager, settingsManager settings.Manager) *handler {
	return &handler{
		accountManager:  accountManager,
		settingsManager: settingsManager,
	}
}

func validateIPAddress(addr netip.Addr) error {
	if addr.IsLoopback() {
		return status.Errorf(status.InvalidArgument, "loopback address range not allowed")
	}

	if addr.IsMulticast() {
		return status.Errorf(status.InvalidArgument, "multicast address range not allowed")
	}

	if addr.Is4() {
		linkLocal, _ := netip.ParsePrefix("169.254.0.0/16")
		if linkLocal.Contains(addr) {
			return status.Errorf(status.InvalidArgument, "link-local address range not allowed")
		}
	} else if addr.Is6() {
		linkLocal, _ := netip.ParsePrefix("fe80::/10")
		if linkLocal.Contains(addr) {
			return status.Errorf(status.InvalidArgument, "IPv6 link-local address range not allowed")
		}
	}

	return nil
}

func validateMinimumSize(prefix netip.Prefix) error {
	addr := prefix.Addr()
	if addr.Is4() && prefix.Bits() > MinNetworkBitsIPv4 {
		return status.Errorf(status.InvalidArgument, "network range too small: minimum size is /%d for IPv4", MinNetworkBitsIPv4)
	}
	if addr.Is6() && prefix.Bits() > MinNetworkBitsIPv6 {
		return status.Errorf(status.InvalidArgument, "network range too small: minimum size is /%d for IPv6", MinNetworkBitsIPv6)
	}
	return nil
}

func (h *handler) validateNetworkRange(ctx context.Context, accountID, userID, networkRange string) error {
	if networkRange == "" {
		return nil
	}

	prefix, err := netip.ParsePrefix(networkRange)
	if err != nil {
		return status.Errorf(status.InvalidArgument, "invalid CIDR format: %v", err)
	}

	if err := validateIPAddress(prefix.Addr()); err != nil {
		return err
	}

	if err := validateMinimumSize(prefix); err != nil {
		return err
	}

	return h.validateCapacity(ctx, accountID, userID, prefix)
}

func (h *handler) validateCapacity(ctx context.Context, accountID, userID string, prefix netip.Prefix) error {
	peers, err := h.accountManager.GetPeers(ctx, accountID, userID, "", "")
	if err != nil {
		return status.Errorf(status.Internal, "get peer count: %v", err)
	}

	maxHosts := calculateMaxHosts(prefix)
	requiredAddresses := calculateRequiredAddresses(len(peers))

	if maxHosts < requiredAddresses {
		return status.Errorf(status.InvalidArgument,
			"network range too small: need at least %d addresses for %d peers + buffer, but range provides %d",
			requiredAddresses, len(peers), maxHosts)
	}

	return nil
}

func calculateMaxHosts(prefix netip.Prefix) int64 {
	availableAddresses := prefix.Addr().BitLen() - prefix.Bits()
	maxHosts := int64(1) << availableAddresses

	if prefix.Addr().Is4() {
		maxHosts -= 2 // network and broadcast addresses
	}

	return maxHosts
}

func calculateRequiredAddresses(peerCount int) int64 {
	requiredAddresses := int64(peerCount) + int64(float64(peerCount)*PeerBufferPercentage)
	if requiredAddresses < MinRequiredAddresses {
		requiredAddresses = MinRequiredAddresses
	}
	return requiredAddresses
}

// getAllAccounts is HTTP GET handler that returns a list of accounts. Effectively returns just a single account.
func (h *handler) getAllAccounts(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	meta, err := h.accountManager.GetAccountMeta(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	settings, err := h.settingsManager.GetSettings(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	onboarding, err := h.accountManager.GetAccountOnboarding(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toAccountResponse(accountID, settings, meta, onboarding)
	util.WriteJSONObject(r.Context(), w, []*api.Account{resp})
}

// updateAccount is HTTP PUT handler that updates the provided account. Updates only account settings (server.Settings)
func (h *handler) updateAccount(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	_, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	accountID := vars["accountId"]
	if len(accountID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid accountID ID"), w)
		return
	}

	var req api.PutApiAccountsAccountIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	settings := &types.Settings{
		PeerLoginExpirationEnabled: req.Settings.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        time.Duration(float64(time.Second.Nanoseconds()) * float64(req.Settings.PeerLoginExpiration)),
		RegularUsersViewBlocked:    req.Settings.RegularUsersViewBlocked,

		PeerInactivityExpirationEnabled: req.Settings.PeerInactivityExpirationEnabled,
		PeerInactivityExpiration:        time.Duration(float64(time.Second.Nanoseconds()) * float64(req.Settings.PeerInactivityExpiration)),
	}

	if req.Settings.Extra != nil {
		settings.Extra = &types.ExtraSettings{
			PeerApprovalEnabled:      req.Settings.Extra.PeerApprovalEnabled,
			FlowEnabled:              req.Settings.Extra.NetworkTrafficLogsEnabled,
			FlowPacketCounterEnabled: req.Settings.Extra.NetworkTrafficPacketCounterEnabled,
		}
	}

	if req.Settings.JwtGroupsEnabled != nil {
		settings.JWTGroupsEnabled = *req.Settings.JwtGroupsEnabled
	}
	if req.Settings.GroupsPropagationEnabled != nil {
		settings.GroupsPropagationEnabled = *req.Settings.GroupsPropagationEnabled
	}
	if req.Settings.JwtGroupsClaimName != nil {
		settings.JWTGroupsClaimName = *req.Settings.JwtGroupsClaimName
	}
	if req.Settings.JwtAllowGroups != nil {
		settings.JWTAllowGroups = *req.Settings.JwtAllowGroups
	}
	if req.Settings.RoutingPeerDnsResolutionEnabled != nil {
		settings.RoutingPeerDNSResolutionEnabled = *req.Settings.RoutingPeerDnsResolutionEnabled
	}
	if req.Settings.DnsDomain != nil {
		settings.DNSDomain = *req.Settings.DnsDomain
	}
	if req.Settings.LazyConnectionEnabled != nil {
		settings.LazyConnectionEnabled = *req.Settings.LazyConnectionEnabled
	}
	if req.Settings.NetworkRange != nil {
		if err := h.validateNetworkRange(r.Context(), accountID, userID, *req.Settings.NetworkRange); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		settings.NetworkRange = *req.Settings.NetworkRange
	}

	var onboarding *types.AccountOnboarding
	if req.Onboarding != nil {
		onboarding = &types.AccountOnboarding{
			OnboardingFlowPending: req.Onboarding.OnboardingFlowPending,
			SignupFormPending:     req.Onboarding.SignupFormPending,
		}
	}

	updatedOnboarding, err := h.accountManager.UpdateAccountOnboarding(r.Context(), accountID, userID, onboarding)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	updatedSettings, err := h.accountManager.UpdateAccountSettings(r.Context(), accountID, userID, settings)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	meta, err := h.accountManager.GetAccountMeta(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toAccountResponse(accountID, updatedSettings, meta, updatedOnboarding)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// deleteAccount is a HTTP DELETE handler to delete an account
func (h *handler) deleteAccount(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetAccountID := vars["accountId"]
	if len(targetAccountID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid account ID"), w)
		return
	}

	err = h.accountManager.DeleteAccount(r.Context(), targetAccountID, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func toAccountResponse(accountID string, settings *types.Settings, meta *types.AccountMeta, onboarding *types.AccountOnboarding) *api.Account {
	jwtAllowGroups := settings.JWTAllowGroups
	if jwtAllowGroups == nil {
		jwtAllowGroups = []string{}
	}

	apiSettings := api.AccountSettings{
		PeerLoginExpiration:             int(settings.PeerLoginExpiration.Seconds()),
		PeerLoginExpirationEnabled:      settings.PeerLoginExpirationEnabled,
		PeerInactivityExpiration:        int(settings.PeerInactivityExpiration.Seconds()),
		PeerInactivityExpirationEnabled: settings.PeerInactivityExpirationEnabled,
		GroupsPropagationEnabled:        &settings.GroupsPropagationEnabled,
		JwtGroupsEnabled:                &settings.JWTGroupsEnabled,
		JwtGroupsClaimName:              &settings.JWTGroupsClaimName,
		JwtAllowGroups:                  &jwtAllowGroups,
		RegularUsersViewBlocked:         settings.RegularUsersViewBlocked,
		RoutingPeerDnsResolutionEnabled: &settings.RoutingPeerDNSResolutionEnabled,
		LazyConnectionEnabled:           &settings.LazyConnectionEnabled,
		DnsDomain:                       &settings.DNSDomain,
	}

	if settings.NetworkRange != "" {
		apiSettings.NetworkRange = &settings.NetworkRange
	}

	apiOnboarding := api.AccountOnboarding{
		OnboardingFlowPending: onboarding.OnboardingFlowPending,
		SignupFormPending:     onboarding.SignupFormPending,
	}

	if settings.Extra != nil {
		apiSettings.Extra = &api.AccountExtraSettings{
			PeerApprovalEnabled:                settings.Extra.PeerApprovalEnabled,
			NetworkTrafficLogsEnabled:          settings.Extra.FlowEnabled,
			NetworkTrafficPacketCounterEnabled: settings.Extra.FlowPacketCounterEnabled,
		}
	}

	return &api.Account{
		Id:             accountID,
		Settings:       apiSettings,
		CreatedAt:      meta.CreatedAt,
		CreatedBy:      meta.CreatedBy,
		Domain:         meta.Domain,
		DomainCategory: meta.DomainCategory,
		Onboarding:     apiOnboarding,
	}
}
