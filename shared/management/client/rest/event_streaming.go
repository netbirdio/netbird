package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// EventStreamingAPI APIs for event streaming integrations
type EventStreamingAPI struct {
	c *Client
}

// List retrieves all event streaming integrations
// See more: https://docs.netbird.io/api/resources/event-streaming#list-all-event-streaming-integrations
func (a *EventStreamingAPI) List(ctx context.Context) ([]api.IntegrationResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/event-streaming", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IntegrationResponse](resp)
	return ret, err
}

// Get retrieves a specific event streaming integration by ID
// See more: https://docs.netbird.io/api/resources/event-streaming#retrieve-an-event-streaming-integration
func (a *EventStreamingAPI) Get(ctx context.Context, integrationID int) (*api.IntegrationResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/event-streaming/"+strconv.Itoa(integrationID), nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IntegrationResponse](resp)
	return &ret, err
}

// Create creates a new event streaming integration
// See more: https://docs.netbird.io/api/resources/event-streaming#create-an-event-streaming-integration
func (a *EventStreamingAPI) Create(ctx context.Context, request api.CreateIntegrationRequest) (*api.IntegrationResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/event-streaming", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IntegrationResponse](resp)
	return &ret, err
}

// Update updates an existing event streaming integration
// See more: https://docs.netbird.io/api/resources/event-streaming#update-an-event-streaming-integration
func (a *EventStreamingAPI) Update(ctx context.Context, integrationID int, request api.CreateIntegrationRequest) (*api.IntegrationResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/event-streaming/"+strconv.Itoa(integrationID), bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IntegrationResponse](resp)
	return &ret, err
}

// Delete deletes an event streaming integration
// See more: https://docs.netbird.io/api/resources/event-streaming#delete-an-event-streaming-integration
func (a *EventStreamingAPI) Delete(ctx context.Context, integrationID int) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/event-streaming/"+strconv.Itoa(integrationID), nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}
