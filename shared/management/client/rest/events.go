package rest

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// EventsAPI APIs for Events, do not use directly
type EventsAPI struct {
	c *Client
}

// List list all events
// See more: https://docs.netbird.io/api/resources/events#list-all-events
func (a *EventsAPI) List(ctx context.Context) ([]api.Event, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/events", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Event](resp)
	return ret, err
}
