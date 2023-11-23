package events

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
)

type EventsManager struct {
	store activity.Store
}

func NewEventsManager(store activity.Store) *EventsManager {
	return &EventsManager{
		store: store,
	}
}

// GetEvents returns a list of activity events of an account
func (em *EventsManager) GetEvents(accountID, userID string) ([]*activity.Event, error) {
	events, err := em.store.Get(accountID, 0, 10000, true)
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

func (em *EventsManager) StoreEvent(initiatorID, targetID, accountID string, activityID activity.Activity,
	meta map[string]any) {

	go func() {
		_, err := em.store.Save(&activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activityID,
			InitiatorID: initiatorID,
			TargetID:    targetID,
			AccountID:   accountID,
			Meta:        meta,
		})
		if err != nil {
			// todo add metric
			log.Errorf("received an error while storing an activity event, error: %s", err)
		}
	}()

}
