package server

import (
	"context"
	"slices"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

func validateDeleteGroup(ctx context.Context, transaction store.Store, group *types.Group, userID string, flowGroups []string) error {
	// disable a deleting integration group if the initiator is not an admin service user
	if group.Issued == types.GroupIssuedIntegration {
		executingUser, err := transaction.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
		if err != nil {
			return status.Errorf(status.Internal, "failed to get user")
		}
		if executingUser.Role != types.UserRoleAdmin || !executingUser.IsServiceUser {
			return status.Errorf(status.PermissionDenied, "only service users with admin power can delete integration group")
		}
	}

	if group.IsGroupAll() {
		return status.Errorf(status.InvalidArgument, "deleting group ALL is not allowed")
	}

	if len(group.Resources) > 0 {
		return &GroupLinkError{"network resource", group.Resources[0].ID}
	}

	if slices.Contains(flowGroups, group.ID) {
		return &GroupLinkError{"settings", "traffic event logging"}
	}

	if isLinked, linkedRoute := isGroupLinkedToRoute(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"route", string(linkedRoute.NetID)}
	}

	if isLinked, linkedDns := isGroupLinkedToDns(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"name server groups", linkedDns.Name}
	}

	if isLinked, linkedPolicy := isGroupLinkedToPolicy(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"policy", linkedPolicy.Name}
	}

	if isLinked, linkedSetupKey := isGroupLinkedToSetupKey(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"setup key", linkedSetupKey.Name}
	}

	if isLinked, linkedUser := isGroupLinkedToUser(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"user", linkedUser.Id}
	}

	if isLinked, linkedRouter := isGroupLinkedToNetworkRouter(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"network router", linkedRouter.ID}
	}

	return checkGroupLinkedToSettings(ctx, transaction, group)
}

// checkGroupLinkedToSettings verifies if a group is linked to any settings in the account.
func checkGroupLinkedToSettings(ctx context.Context, transaction store.Store, group *types.Group) error {
	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthNone, group.AccountID)
	if err != nil {
		return status.Errorf(status.Internal, "failed to get DNS settings")
	}

	if slices.Contains(dnsSettings.DisabledManagementGroups, group.ID) {
		return &GroupLinkError{"disabled DNS management groups", group.Name}
	}

	settings, err := transaction.GetAccountSettings(ctx, store.LockingStrengthNone, group.AccountID)
	if err != nil {
		return status.Errorf(status.Internal, "failed to get account settings")
	}

	if settings.Extra != nil && slices.Contains(settings.Extra.IntegratedValidatorGroups, group.ID) {
		return &GroupLinkError{"integrated validator", group.Name}
	}

	return nil
}

// isGroupLinkedToRoute checks if a group is linked to any route in the account.
func isGroupLinkedToRoute(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *route.Route) {
	routes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving routes while checking group linkage: %v", err)
		return false, nil
	}

	for _, r := range routes {
		isLinked := slices.Contains(r.Groups, groupID) ||
			slices.Contains(r.PeerGroups, groupID) ||
			slices.Contains(r.AccessControlGroups, groupID)
		if isLinked {
			return true, r
		}
	}

	return false, nil
}

// isGroupLinkedToPolicy checks if a group is linked to any policy in the account.
func isGroupLinkedToPolicy(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *types.Policy) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving policies while checking group linkage: %v", err)
		return false, nil
	}

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if slices.Contains(rule.Sources, groupID) || slices.Contains(rule.Destinations, groupID) {
				return true, policy
			}
		}
	}
	return false, nil
}

// isGroupLinkedToDns checks if a group is linked to any nameserver group in the account.
func isGroupLinkedToDns(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *nbdns.NameServerGroup) {
	nameServerGroups, err := transaction.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving name server groups while checking group linkage: %v", err)
		return false, nil
	}

	for _, dns := range nameServerGroups {
		for _, g := range dns.Groups {
			if g == groupID {
				return true, dns
			}
		}
	}

	return false, nil
}

// isGroupLinkedToSetupKey checks if a group is linked to any setup key in the account.
func isGroupLinkedToSetupKey(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *types.SetupKey) {
	setupKeys, err := transaction.GetAccountSetupKeys(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving setup keys while checking group linkage: %v", err)
		return false, nil
	}

	for _, setupKey := range setupKeys {
		if slices.Contains(setupKey.AutoGroups, groupID) {
			return true, setupKey
		}
	}
	return false, nil
}

// isGroupLinkedToUser checks if a group is linked to any user in the account.
func isGroupLinkedToUser(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *types.User) {
	users, err := transaction.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving users while checking group linkage: %v", err)
		return false, nil
	}

	for _, user := range users {
		if slices.Contains(user.AutoGroups, groupID) {
			return true, user
		}
	}
	return false, nil
}

// isGroupLinkedToNetworkRouter checks if a group is linked to any network router in the account.
func isGroupLinkedToNetworkRouter(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *routerTypes.NetworkRouter) {
	routers, err := transaction.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving network routers while checking group linkage: %v", err)
		return false, nil
	}

	for _, router := range routers {
		if slices.Contains(router.PeerGroups, groupID) {
			return true, router
		}
	}
	return false, nil
}

// areGroupChangesAffectPeers checks if any changes to the specified groups will affect peers.
func areGroupChangesAffectPeers(ctx context.Context, transaction store.Store, accountID string, groupIDs []string) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}

	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, err
	}

	for _, groupID := range groupIDs {
		if slices.Contains(dnsSettings.DisabledManagementGroups, groupID) {
			return true, nil
		}
		if linked, _ := isGroupLinkedToDns(ctx, transaction, accountID, groupID); linked {
			return true, nil
		}
		if linked, _ := isGroupLinkedToPolicy(ctx, transaction, accountID, groupID); linked {
			return true, nil
		}
		if linked, _ := isGroupLinkedToRoute(ctx, transaction, accountID, groupID); linked {
			return true, nil
		}
		if linked, _ := isGroupLinkedToNetworkRouter(ctx, transaction, accountID, groupID); linked {
			return true, nil
		}
	}

	return false, nil
}
