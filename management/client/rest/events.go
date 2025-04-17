package rest

import (
	"context"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// EventsAPI APIs for Events, do not use directly
type EventsAPI struct {
	c *Client
}

// List list all events
// See more: https://docs.netbird.io/api/resources/events#list-all-events
func (a *EventsAPI) List(ctx context.Context) ([]api.Event, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/events", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[[]api.Event](resp)
	return ret, err
}
