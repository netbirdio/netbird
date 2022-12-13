package server

import (
	"fmt"
	"github.com/netbirdio/netbird/management/server/activity"
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
