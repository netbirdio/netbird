package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// RoutesAPI APIs for Routes, do not use directly
type RoutesAPI struct {
	c *Client
}

// List list all routes
// See more: https://docs.netbird.io/api/resources/routes#list-all-routes
func (a *RoutesAPI) List(ctx context.Context) ([]api.Route, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/routes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[[]api.Route](resp)
	return ret, err
}

// Get get route info
// See more: https://docs.netbird.io/api/resources/routes#retrieve-a-route
func (a *RoutesAPI) Get(ctx context.Context, routeID string) (*api.Route, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/routes/"+routeID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.Route](resp)
	return &ret, err
}

// Create create new route
// See more: https://docs.netbird.io/api/resources/routes#create-a-route
func (a *RoutesAPI) Create(ctx context.Context, request api.PostApiRoutesJSONRequestBody) (*api.Route, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.newRequest(ctx, "POST", "/api/routes", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.Route](resp)
	return &ret, err
}

// Update update route info
// See more: https://docs.netbird.io/api/resources/routes#update-a-route
func (a *RoutesAPI) Update(ctx context.Context, routeID string, request api.PutApiRoutesRouteIdJSONRequestBody) (*api.Route, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.newRequest(ctx, "PUT", "/api/routes/"+routeID, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.Route](resp)
	return &ret, err
}

// Delete delete route
// See more: https://docs.netbird.io/api/resources/routes#delete-a-route
func (a *RoutesAPI) Delete(ctx context.Context, routeID string) error {
	resp, err := a.c.newRequest(ctx, "DELETE", "/api/routes/"+routeID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
