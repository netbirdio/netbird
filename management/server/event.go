package server

import (
	"fmt"
	"github.com/netbirdio/netbird/management/server/activity"
	log "github.com/sirupsen/logrus"
	"time"
)

// GetEvents returns a list of activity events of an account
func (am *DefaultAccountManager) GetEvents(accountID, userID string) ([]*activity.Event, error) {
	events, err := am.eventStore.Get(accountID, 0, 10000, true)
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

func (am *DefaultAccountManager) storeEvent(initiatorID, targetID, accountID string, activityID activity.Activity,
	meta map[string]any) {

	go func() {
		_, err := am.eventStore.Save(&activity.Event{
			Timestamp:   time.Now(),
			Activity:    activityID,
			InitiatorID: initiatorID,
			TargetID:    targetID,
			AccountID:   accountID,
			Meta:        meta,
		})
		if err != nil {
			//todo add metric
			log.Errorf("received an error while storing an activity event, error: %s", err)
		}
	}()

}
