package server

import "github.com/netbirdio/netbird/management/server/activity"

// GetEvents returns a list of activity events of an account
func (am *DefaultAccountManager) GetEvents(accountID, userID string) ([]*activity.Event, error) {
	return am.eventStore.Get(accountID, 0, 1000, true)
}
