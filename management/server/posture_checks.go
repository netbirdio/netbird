package server

import (
	"context"
	"slices"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

const (
	errMsgPostureAdminOnly = "only users with admin power are allowed to view posture checks"
)

func (am *DefaultAccountManager) GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() {
		return nil, status.Errorf(status.PermissionDenied, errMsgPostureAdminOnly)
	}

	for _, postureChecks := range account.PostureChecks {
		if postureChecks.ID == postureChecksID {
			return postureChecks, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "posture checks with ID %s not found", postureChecksID)
}

func (am *DefaultAccountManager) SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, errMsgPostureAdminOnly)
	}

	if err := postureChecks.Validate(); err != nil {
		return status.Errorf(status.InvalidArgument, err.Error()) //nolint
	}

	exists, uniqName := am.savePostureChecks(account, postureChecks)

	// we do not allow create new posture checks with non uniq name
	if !exists && !uniqName {
		return status.Errorf(status.PreconditionFailed, "Posture check name should be unique")
	}

	action := activity.PostureCheckCreated
	if exists {
		action = activity.PostureCheckUpdated
		account.Network.IncSerial()
	}

	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, action, postureChecks.EventMeta())

	isLinked, linkedPolicy := isPostureCheckLinkedToPolicy(account, postureChecks.ID)
	if exists && isLinked && anyGroupHasPeers(account, linkedPolicy.ruleGroups()) {
		am.updateAccountPeers(ctx, account)
	}

	return nil
}

func (am *DefaultAccountManager) DeletePostureChecks(ctx context.Context, accountID, postureChecksID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, errMsgPostureAdminOnly)
	}

	postureChecks, err := am.deletePostureChecks(account, postureChecksID)
	if err != nil {
		return err
	}

	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, postureChecks.ID, accountID, activity.PostureCheckDeleted, postureChecks.EventMeta())

	return nil
}

func (am *DefaultAccountManager) ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() {
		return nil, status.Errorf(status.PermissionDenied, errMsgPostureAdminOnly)
	}

	return account.PostureChecks, nil
}

func (am *DefaultAccountManager) savePostureChecks(account *Account, postureChecks *posture.Checks) (exists, uniqName bool) {
	uniqName = true
	for i, p := range account.PostureChecks {
		if !exists && p.ID == postureChecks.ID {
			account.PostureChecks[i] = postureChecks
			exists = true
		}
		if p.Name == postureChecks.Name {
			uniqName = false
		}
	}
	if !exists {
		account.PostureChecks = append(account.PostureChecks, postureChecks)
	}
	return
}

func (am *DefaultAccountManager) deletePostureChecks(account *Account, postureChecksID string) (*posture.Checks, error) {
	postureChecksIdx := -1
	for i, postureChecks := range account.PostureChecks {
		if postureChecks.ID == postureChecksID {
			postureChecksIdx = i
			break
		}
	}
	if postureChecksIdx < 0 {
		return nil, status.Errorf(status.NotFound, "posture checks with ID %s doesn't exist", postureChecksID)
	}

	// Check if posture check is linked to any policy
	if isLinked, linkedPolicy := isPostureCheckLinkedToPolicy(account, postureChecksID); isLinked {
		return nil, status.Errorf(status.PreconditionFailed, "posture checks have been linked to policy: %s", linkedPolicy.Name)
	}

	postureChecks := account.PostureChecks[postureChecksIdx]
	account.PostureChecks = append(account.PostureChecks[:postureChecksIdx], account.PostureChecks[postureChecksIdx+1:]...)

	return postureChecks, nil
}

// getPeerPostureChecks returns the posture checks applied for a given peer.
func (am *DefaultAccountManager) getPeerPostureChecks(account *Account, peer *nbpeer.Peer) []*posture.Checks {
	peerPostureChecks := make(map[string]posture.Checks)

	if len(account.PostureChecks) == 0 {
		return nil
	}

	for _, policy := range account.Policies {
		if !policy.Enabled {
			continue
		}

		if isPeerInPolicySourceGroups(peer.ID, account, policy) {
			addPolicyPostureChecks(account, policy, peerPostureChecks)
		}
	}

	postureChecksList := make([]*posture.Checks, 0, len(peerPostureChecks))
	for _, check := range peerPostureChecks {
		checkCopy := check
		postureChecksList = append(postureChecksList, &checkCopy)
	}

	return postureChecksList
}

// isPeerInPolicySourceGroups checks if a peer is present in any of the policy rule source groups.
func isPeerInPolicySourceGroups(peerID string, account *Account, policy *Policy) bool {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		for _, sourceGroup := range rule.Sources {
			group, ok := account.Groups[sourceGroup]
			if ok && slices.Contains(group.Peers, peerID) {
				return true
			}
		}
	}

	return false
}

func addPolicyPostureChecks(account *Account, policy *Policy, peerPostureChecks map[string]posture.Checks) {
	for _, sourcePostureCheckID := range policy.SourcePostureChecks {
		for _, postureCheck := range account.PostureChecks {
			if postureCheck.ID == sourcePostureCheckID {
				peerPostureChecks[sourcePostureCheckID] = *postureCheck
			}
		}
	}
}

func isPostureCheckLinkedToPolicy(account *Account, postureChecksID string) (bool, *Policy) {
	for _, policy := range account.Policies {
		if slices.Contains(policy.SourcePostureChecks, postureChecksID) {
			return true, policy
		}
	}
	return false, nil
}
