package server

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func isEnabled() bool {
	response := os.Getenv("NB_EVENT_ACTIVITY_LOG_ENABLED")
	return response == "" || response == "true"
}

// GetEvents returns a list of activity events of an account
func (am *DefaultAccountManager) GetEvents(ctx context.Context, accountID, userID string) ([]*activity.Event, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Events, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
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

	err = am.fillEventsWithUserInfo(ctx, events, accountID, userID)
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
				Activity:    activityID.(activity.Activity),
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

func (am *DefaultAccountManager) fillEventsWithUserInfo(ctx context.Context, events []*activity.Event, accountId string, userId string) error {
	eventUserInfo, err := am.getEventsUserInfo(ctx, events, accountId, userId)
	if err != nil {
		return err
	}

	for _, event := range events {
		if !fillEventInitiatorInfo(eventUserInfo, event) {
			log.WithContext(ctx).Warnf("failed to resolve user info for initiator: %s", event.InitiatorID)
		}

		fillEventTargetInfo(eventUserInfo, event)
	}
	return nil
}

func (am *DefaultAccountManager) getEventsUserInfo(ctx context.Context, events []*activity.Event, accountId string, userId string) (map[string]eventUserInfo, error) {
	accountUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountId)
	if err != nil {
		return nil, err
	}

	// @note check whether using a external initiator user here is an issue
	userInfos, err := am.BuildUserInfosForAccount(ctx, accountId, userId, accountUsers)
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

	return am.getEventsExternalUserInfo(ctx, externalUserIds, eventUserInfos)
}

func (am *DefaultAccountManager) getEventsExternalUserInfo(ctx context.Context, externalUserIds []string, eventUserInfos map[string]eventUserInfo) (map[string]eventUserInfo, error) {
	fetched := make(map[string]struct{})
	externalUsers := []*types.User{}
	for _, id := range externalUserIds {
		if _, ok := fetched[id]; ok {
			continue
		}

		externalUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, id)
		if err != nil {
			// @todo consider logging
			continue
		}

		fetched[id] = struct{}{}
		externalUsers = append(externalUsers, externalUser)
	}

	usersByExternalAccount := map[string][]*types.User{}
	for _, u := range externalUsers {
		if _, ok := usersByExternalAccount[u.AccountID]; !ok {
			usersByExternalAccount[u.AccountID] = make([]*types.User, 0)
		}
		usersByExternalAccount[u.AccountID] = append(usersByExternalAccount[u.AccountID], u)
	}

	for externalAccountId, externalUsers := range usersByExternalAccount {
		externalUserInfos, err := am.BuildUserInfosForAccount(ctx, externalAccountId, "", externalUsers)
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
	}

	return eventUserInfos, nil
}

func fillEventTargetInfo(eventUserInfo map[string]eventUserInfo, event *activity.Event) {
	userInfo, ok := eventUserInfo[event.TargetID]
	if !ok {
		return
	}

	if event.Meta == nil {
		event.Meta = make(map[string]any)
	}

	event.Meta["email"] = userInfo.email
	event.Meta["username"] = userInfo.name
}

func fillEventInitiatorInfo(eventUserInfo map[string]eventUserInfo, event *activity.Event) bool {
	userInfo, ok := eventUserInfo[event.InitiatorID]
	if !ok {
		return false
	}

	if event.InitiatorEmail == "" {
		event.InitiatorEmail = userInfo.email
	}

	if event.InitiatorName == "" {
		event.InitiatorName = userInfo.name
	}

	if event.AccountID != userInfo.accountId {
		if event.Meta == nil {
			event.Meta = make(map[string]any)
		}

		event.Meta["external"] = true
	}
	return true
}
