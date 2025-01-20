package server

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
)

func isEnabled() bool {
	response := os.Getenv("NB_EVENT_ACTIVITY_LOG_ENABLED")
	return response == "" || response == "true"
}

// GetEvents returns a list of activity events of an account
func (am *DefaultAccountManager) GetEvents(ctx context.Context, accountID, userID string) ([]*activity.Event, error) {
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
