package server

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func isEnabled() bool {
	response := os.Getenv("NB_EVENT_ACTIVITY_LOG_ENABLED")
	return response == "" || response == "true"
}

// GetEvents returns a list of activity events of an account
func (am *DefaultAccountManager) GetEvents(ctx context.Context, accountID, userID string) ([]*activity.Event, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if err := am.permissionsManager.ValidateAccountAccess(ctx, accountID, user); err != nil {
		return nil, err
	}

	if !(user.HasAdminPower() || user.IsServiceUser) {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power can view events")
	}

	events, err := am.eventStore.Get(ctx, accountID, 0, 10000, true)
	if err != nil {
		return nil, err
	}

	// this is a workaround for duplicate activity.UserJoined events that might occur when a user redeems invite.
	// we will need to find a better way to handle this.
	filtered := make([]*activity.Event, 0)
	dups := make(map[string]struct{})
	for _, event := range events {
		if event.Activity == activity.UserJoined {
			key := event.TargetID + event.InitiatorID + event.AccountID + fmt.Sprint(event.Activity)
			_, duplicate := dups[key]
			if duplicate {
				continue
			} else {
				dups[key] = struct{}{}
			}
		}
		filtered = append(filtered, event)
	}

	err = am.fillEventsWithUserInfo(ctx, events, accountID, user)
	if err != nil {
		return nil, err
	}

	return filtered, nil
}

func (am *DefaultAccountManager) StoreEvent(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
	if isEnabled() {
		go func() {
			_, err := am.eventStore.Save(ctx, &activity.Event{
				Timestamp:   time.Now().UTC(),
				Activity:    activityID,
				InitiatorID: initiatorID,
				TargetID:    targetID,
				AccountID:   accountID,
				Meta:        meta,
			})
			if err != nil {
				// todo add metric
				log.WithContext(ctx).Errorf("received an error while storing an activity event, error: %s", err)
			}
		}()
	}
}

type eventUserInfo struct {
	email     string
	name      string
	accountId string
}

func (am *DefaultAccountManager) fillEventsWithUserInfo(ctx context.Context, events []*activity.Event, accountId string, user *types.User) error {
	eventUserInfo, err := am.getEventsUserInfo(ctx, events, accountId, user)
	if err != nil {
		return err
	}

	for _, event := range events {
		initiatorUserInfo, ok := eventUserInfo[event.InitiatorID]
		if !ok {
			log.WithContext(ctx).Warnf("failed to resolve user info for initiator: %s", event.InitiatorID)
		}

		if event.InitiatorEmail == "" && ok {
			event.InitiatorEmail = initiatorUserInfo.email
		}

		if event.InitiatorName == "" && ok {
			// here to allowed to be empty because in the first release we did not store the name
			event.InitiatorName = initiatorUserInfo.name
		}

		if ok && event.AccountID != initiatorUserInfo.accountId {
			if event.Meta == nil {
				event.Meta = make(map[string]any)
			}

			event.Meta["external"] = true
		}

		targetUserInfo, ok := eventUserInfo[event.TargetID]
		if !ok {
			continue
		}

		if event.Meta == nil {
			event.Meta = make(map[string]any)
		}

		event.Meta["email"] = targetUserInfo.email
		event.Meta["username"] = targetUserInfo.name
	}
	return nil
}

func (am *DefaultAccountManager) getEventsUserInfo(ctx context.Context, events []*activity.Event, accountId string, user *types.User) (map[string]eventUserInfo, error) {
	accountUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthShare, accountId)
	if err != nil {
		return nil, err
	}

	// @note check whether using a external initiator user here is an issue
	userInfos, err := am.BuildUserInfosForAccount(ctx, accountId, user.Id, accountUsers)
	if err != nil {
		return nil, err
	}

	eventUserInfos := make(map[string]eventUserInfo)
	for i, k := range userInfos {
		eventUserInfos[i] = eventUserInfo{
			email:     k.Email,
			name:      k.Name,
			accountId: accountId,
		}
	}

	externalUserIds := []string{}
	for _, event := range events {
		if _, ok := eventUserInfos[event.InitiatorID]; ok {
			continue
		}

		if event.InitiatorID == activity.SystemInitiator ||
			event.InitiatorID == accountId ||
			event.Activity == activity.PeerAddedWithSetupKey {
			// @todo other events to be excluded if never initiated by a user
			continue
		}

		externalUserIds = append(externalUserIds, event.InitiatorID)
	}

	if len(externalUserIds) == 0 {
		return eventUserInfos, nil
	}

	return am.getEventsExternalUserInfo(ctx, externalUserIds, eventUserInfos, user)
}

func (am *DefaultAccountManager) getEventsExternalUserInfo(ctx context.Context, externalUserIds []string, eventUserInfos map[string]eventUserInfo, user *types.User) (map[string]eventUserInfo, error) {
	externalAccountId := ""
	fetched := make(map[string]struct{})
	externalUsers := []*types.User{}
	for _, id := range externalUserIds {
		if _, ok := fetched[id]; ok {
			continue
		}

		externalUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, id)
		if err != nil {
			// @todo consider logging
			continue
		}

		if externalAccountId != "" && externalAccountId != externalUser.AccountID {
			return nil, fmt.Errorf("multiple external user accounts in events")
		}

		if externalAccountId == "" {
			externalAccountId = externalUser.AccountID
		}

		fetched[id] = struct{}{}
		externalUsers = append(externalUsers, externalUser)
	}

	// if we couldn't determine an account, return what we have
	if externalAccountId == "" {
		log.WithContext(ctx).Warnf("failed to determine external user account from users: %v", externalUserIds)
		return eventUserInfos, nil
	}

	externalUserInfos, err := am.BuildUserInfosForAccount(ctx, externalAccountId, user.Id, externalUsers)
	if err != nil {
		return nil, err
	}

	for i, k := range externalUserInfos {
		eventUserInfos[i] = eventUserInfo{
			email:     k.Email,
			name:      k.Name,
			accountId: externalAccountId,
		}
	}

	return eventUserInfos, nil
}
