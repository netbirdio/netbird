package accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/gorilla/mux"

	goversion "github.com/hashicorp/go-version"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	// PeerBufferPercentage is the percentage of peers to add as buffer for network range calculations
	PeerBufferPercentage = 0.5
	// MinRequiredAddresses is the minimum number of addresses required in a network range
	MinRequiredAddresses = 10
	// MinNetworkBits is the minimum prefix length for IPv4 network ranges (e.g., /29 gives 8 addresses, /28 gives 16)
	MinNetworkBitsIPv4 = 28
	// MinNetworkBitsIPv6 is the minimum prefix length for IPv6 network ranges
	MinNetworkBitsIPv6      = 120
	disableAutoUpdate       = "disabled"
	autoUpdateLatestVersion = "latest"
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

	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return status.Errorf(status.InvalidArgument, "link-local address range not allowed")
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

func (h *handler) validateNetworkRange(ctx context.Context, accountID, userID string, networkRange netip.Prefix) error {
	if !networkRange.IsValid() {
		return nil
	}

	if err := validateIPAddress(networkRange.Addr()); err != nil {
		return err
	}

	if err := validateMinimumSize(networkRange); err != nil {
		return err
	}

	return h.validateCapacity(ctx, accountID, userID, networkRange)
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

func (h *handler) updateAccountRequestSettings(req api.PutApiAccountsAccountIdJSONRequestBody) (*types.Settings, error) {
	returnSettings := &types.Settings{
		PeerLoginExpirationEnabled: req.Settings.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        time.Duration(float64(time.Second.Nanoseconds()) * float64(req.Settings.PeerLoginExpiration)),
		RegularUsersViewBlocked:    req.Settings.RegularUsersViewBlocked,

		PeerInactivityExpirationEnabled: req.Settings.PeerInactivityExpirationEnabled,
		PeerInactivityExpiration:        time.Duration(float64(time.Second.Nanoseconds()) * float64(req.Settings.PeerInactivityExpiration)),
	}

	if req.Settings.Extra != nil {
		returnSettings.Extra = &types.ExtraSettings{
			PeerApprovalEnabled:      req.Settings.Extra.PeerApprovalEnabled,
			UserApprovalRequired:     req.Settings.Extra.UserApprovalRequired,
			FlowEnabled:              req.Settings.Extra.NetworkTrafficLogsEnabled,
			FlowGroups:               req.Settings.Extra.NetworkTrafficLogsGroups,
			FlowPacketCounterEnabled: req.Settings.Extra.NetworkTrafficPacketCounterEnabled,
		}
	}

	if req.Settings.JwtGroupsEnabled != nil {
		returnSettings.JWTGroupsEnabled = *req.Settings.JwtGroupsEnabled
	}
	if req.Settings.GroupsPropagationEnabled != nil {
		returnSettings.GroupsPropagationEnabled = *req.Settings.GroupsPropagationEnabled
	}
	if req.Settings.JwtGroupsClaimName != nil {
		returnSettings.JWTGroupsClaimName = *req.Settings.JwtGroupsClaimName
	}
	if req.Settings.JwtAllowGroups != nil {
		returnSettings.JWTAllowGroups = *req.Settings.JwtAllowGroups
	}
	if req.Settings.RoutingPeerDnsResolutionEnabled != nil {
		returnSettings.RoutingPeerDNSResolutionEnabled = *req.Settings.RoutingPeerDnsResolutionEnabled
	}
	if req.Settings.DnsDomain != nil {
		returnSettings.DNSDomain = *req.Settings.DnsDomain
	}
	if req.Settings.LazyConnectionEnabled != nil {
		returnSettings.LazyConnectionEnabled = *req.Settings.LazyConnectionEnabled
	}
	if req.Settings.AutoUpdateVersion != nil {
		_, err := goversion.NewSemver(*req.Settings.AutoUpdateVersion)
		if *req.Settings.AutoUpdateVersion == autoUpdateLatestVersion ||
			*req.Settings.AutoUpdateVersion == disableAutoUpdate ||
			err == nil {
			returnSettings.AutoUpdateVersion = *req.Settings.AutoUpdateVersion
		} else if *req.Settings.AutoUpdateVersion != "" {
			return nil, fmt.Errorf("invalid AutoUpdateVersion")
		}
	}

	return returnSettings, nil
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

	settings, err := h.updateAccountRequestSettings(req)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if req.Settings.NetworkRange != nil && *req.Settings.NetworkRange != "" {
		prefix, err := netip.ParsePrefix(*req.Settings.NetworkRange)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid CIDR format: %v", err), w)
			return
		}
		if err := h.validateNetworkRange(r.Context(), accountID, userID, prefix); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		settings.NetworkRange = prefix
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
		AutoUpdateVersion:               &settings.AutoUpdateVersion,
		EmbeddedIdpEnabled:              &settings.EmbeddedIdpEnabled,
		LocalAuthDisabled:               &settings.LocalAuthDisabled,
	}

	if settings.NetworkRange.IsValid() {
		networkRangeStr := settings.NetworkRange.String()
		apiSettings.NetworkRange = &networkRangeStr
	}

	apiOnboarding := api.AccountOnboarding{
		OnboardingFlowPending: onboarding.OnboardingFlowPending,
		SignupFormPending:     onboarding.SignupFormPending,
	}

	if settings.Extra != nil {
		apiSettings.Extra = &api.AccountExtraSettings{
			PeerApprovalEnabled:                settings.Extra.PeerApprovalEnabled,
			UserApprovalRequired:               settings.Extra.UserApprovalRequired,
			NetworkTrafficLogsEnabled:          settings.Extra.FlowEnabled,
			NetworkTrafficLogsGroups:           settings.Extra.FlowGroups,
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
